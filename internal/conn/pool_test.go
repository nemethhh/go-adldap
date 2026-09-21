package conn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type stubConn struct {
	id     int
	closed atomic.Bool
}

func (s *stubConn) Search(context.Context, SearchRequest) (*SearchResult, error) {
	return &SearchResult{}, nil
}
func (s *stubConn) Add(context.Context, string, []Attribute) error                   { return nil }
func (s *stubConn) Modify(context.Context, string, []Modification, ...Control) error { return nil }
func (s *stubConn) ModifyDN(context.Context, string, string, bool, string) error     { return nil }
func (s *stubConn) Delete(context.Context, string) error                             { return nil }
func (s *stubConn) Close() error                                                     { s.closed.Store(true); return nil }

type countingBinder struct{ n atomic.Int32 }

func (b *countingBinder) Bind(context.Context, Conn) error { b.n.Add(1); return nil }
func (b *countingBinder) Describe() string                 { return "counting binder" }

func newTestPool(t *testing.T, size int) (*Pool, *atomic.Int32, *countingBinder) {
	t.Helper()
	var dials atomic.Int32
	binder := &countingBinder{}
	p := NewPool(PoolOptions{
		Dial: func(context.Context) (Conn, error) {
			return &stubConn{id: int(dials.Add(1))}, nil
		},
		Binder: binder,
		Size:   size,
	})
	t.Cleanup(func() { p.Close() })
	return p, &dials, binder
}

// The pool never exceeds its size, which is what bounds concurrent load on the
// domain controller.
func TestPoolBoundsConcurrency(t *testing.T) {
	p, dials, _ := newTestPool(t, 2)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := p.Acquire(ctx)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			lease.Release()
		}()
	}
	wg.Wait()

	if got := dials.Load(); got > 2 {
		t.Errorf("dialled %d connections, want at most the pool size of 2", got)
	}
}

// A released connection is reused; a discarded one is closed and replaced, and
// the replacement is bound again.
func TestPoolDiscardReplacesAndRebinds(t *testing.T) {
	p, dials, binder := newTestPool(t, 1)
	ctx := context.Background()

	first, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	original := first.Conn().(*stubConn)
	first.Release()

	reused, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if reused.Conn().(*stubConn) != original {
		t.Error("a released connection should be reused")
	}
	reused.Discard()

	if !original.closed.Load() {
		t.Error("a discarded connection must be closed")
	}

	replacement, err := p.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire after discard: %v", err)
	}
	if replacement.Conn().(*stubConn) == original {
		t.Error("a discarded connection must not be handed out again")
	}
	replacement.Release()

	if dials.Load() != 2 {
		t.Errorf("dialled %d times, want 2 (original + replacement)", dials.Load())
	}
	if binder.n.Load() != 2 {
		t.Errorf("bound %d times, want 2: a replacement connection must be re-bound", binder.n.Load())
	}
}

func TestPoolAcquireHonoursCancellation(t *testing.T) {
	p, _, _ := newTestPool(t, 1)
	held, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer held.Release()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire on a cancelled context = %v, want context.Canceled", err)
	}
}

// A dial or bind that fails must give the slot back, or the pool deadlocks
// after Size consecutive failures — which is exactly what a DC restart looks
// like.
func TestPoolReleasesTheSlotWhenDialOrBindFails(t *testing.T) {
	wantErr := errors.New("dial refused")
	p := NewPool(PoolOptions{
		Dial:   func(context.Context) (Conn, error) { return nil, wantErr },
		Binder: &countingBinder{},
		Size:   1,
	})
	defer p.Close()

	for i := 0; i < 3; i++ {
		if _, err := p.Acquire(context.Background()); !errors.Is(err, wantErr) {
			t.Fatalf("Acquire %d = %v, want the dial error", i, err)
		}
	}
}

// Close must not strand a connection that is still out on lease.
func TestPoolCloseThenReleaseClosesTheConnection(t *testing.T) {
	p, _, _ := newTestPool(t, 1)
	lease, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	c := lease.Conn().(*stubConn)

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	lease.Release()

	if !c.closed.Load() {
		t.Error("a connection released after Close must be closed, not pooled")
	}
}
