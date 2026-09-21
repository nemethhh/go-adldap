package conn

import (
	"context"
	"errors"
	"sync"
)

// ErrPoolClosed is returned by Acquire after Close. It is a distinct error
// rather than context.Canceled so a caller can tell "this client is shut down"
// from "my own context went away" — the first is a bug in the caller's
// lifecycle, the second is ordinary cancellation.
var ErrPoolClosed = errors.New("adldap: connection pool is closed")

type PoolOptions struct {
	// Dial opens one unbound connection.
	Dial func(context.Context) (Conn, error)
	// Binder authenticates each connection, including a replacement dialled
	// after a discard.
	Binder Binder
	// Size bounds concurrent connections. Zero means 4.
	Size int
}

// Pool holds bound connections to the pinned domain controller for the
// client's lifetime. Connections are created lazily: a pool that is never used
// never dials.
type Pool struct {
	opts PoolOptions
	sem  chan struct{}

	mu   sync.Mutex
	idle []Conn
	done bool
}

// Lease is one borrowed connection. Exactly one of Release and Discard must be
// called.
type Lease struct {
	p    *Pool
	c    Conn
	once sync.Once
}

func NewPool(o PoolOptions) *Pool {
	if o.Size <= 0 {
		o.Size = 4
	}
	return &Pool{opts: o, sem: make(chan struct{}, o.Size)}
}

// Acquire borrows a bound connection, blocking until one is free.
func (p *Pool) Acquire(ctx context.Context) (*Lease, error) {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	p.mu.Lock()
	if p.done {
		p.mu.Unlock()
		<-p.sem
		return nil, ErrPoolClosed
	}
	if n := len(p.idle); n > 0 {
		c := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return &Lease{p: p, c: c}, nil
	}
	p.mu.Unlock()

	// Every failure below gives the slot back before returning. Holding it
	// would leak one permit per failure, so Size consecutive failures — which
	// is what a DC restart looks like — would deadlock the pool permanently.
	c, err := p.opts.Dial(ctx)
	if err != nil {
		<-p.sem
		return nil, err
	}
	if err := p.opts.Binder.Bind(ctx, c); err != nil {
		c.Close()
		<-p.sem
		return nil, err
	}
	return &Lease{p: p, c: c}, nil
}

// Conn returns the borrowed connection.
func (l *Lease) Conn() Conn { return l.c }

// Release returns the connection to the pool for reuse.
func (l *Lease) Release() {
	l.once.Do(func() {
		l.p.mu.Lock()
		if l.p.done {
			// Close raced ahead of this release. Pooling the connection now
			// would strand it: nothing else will ever drain the idle list.
			l.p.mu.Unlock()
			l.c.Close()
		} else {
			l.p.idle = append(l.p.idle, l.c)
			l.p.mu.Unlock()
		}
		<-l.p.sem
	})
}

// Discard closes the connection instead of returning it. A caller that saw a
// transport-level failure calls this, so the next acquirer gets a freshly
// dialled and freshly bound connection rather than a dead one.
func (l *Lease) Discard() {
	l.once.Do(func() {
		l.c.Close()
		<-l.p.sem
	})
}

// Close closes every idle connection. Leases still outstanding close on
// release.
func (p *Pool) Close() error {
	p.mu.Lock()
	p.done = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()

	var firstErr error
	for _, c := range idle {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
