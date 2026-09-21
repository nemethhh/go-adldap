package adldap_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestReplicationDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	// With Wait off, Create returns with no replication error at all.
	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Fast", Container: d.DNC}); err != nil {
		t.Fatalf("Create with replication off: %v", err)
	}
}

// A replication timeout returns the model AND the error. The object exists;
// only the wait did not finish. Erroring without the model would orphan it.
func TestReplicationTimeoutReturnsTheModel(t *testing.T) {
	ctx := context.Background()
	srv := adtest.Start(t)

	cfg := srv.Config()
	cfg.Timeout = 300 * time.Millisecond // the unreachable target should fail fast
	cfg.Replication = adldap.ReplicationConfig{
		Wait:         true,
		Targets:      []string{"dc02.corp.local"}, // nothing is listening there
		Timeout:      200 * time.Millisecond,
		PollInterval: 50 * time.Millisecond,
	}

	client, err := adldap.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	d := client.Directory()
	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Slow", Container: d.DNC})
	if !errors.Is(err, adcore.ErrReplication) {
		t.Fatalf("want ErrReplication, got %v", err)
	}
	if ou == nil {
		t.Fatal("a replication timeout returned no model; the object exists and would be orphaned")
	}
	if ou.GUID == "" {
		t.Error("the returned model has no GUID")
	}
}

// The pinned DC is never waited on: it already has the write by definition, so
// listing it would make every wait time out against itself.
func TestReplicationSkipsThePinnedServer(t *testing.T) {
	ctx := context.Background()
	srv := adtest.Start(t)

	cfg := srv.Config()
	cfg.Replication = adldap.ReplicationConfig{
		Wait:         true,
		Targets:      []string{cfg.Server},
		Timeout:      200 * time.Millisecond,
		PollInterval: 50 * time.Millisecond,
	}

	client, err := adldap.New(ctx, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	d := client.Directory()
	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Self", Container: d.DNC}); err != nil {
		t.Fatalf("Create waiting only on the pinned DC: %v", err)
	}
}

// force_sync is refused on the PSOpenAD dialect because its cmdlets cannot
// express a rootDSE modify. This backend can, so it must not inherit that
// refusal.
func TestForceSyncIsAccepted(t *testing.T) {
	ctx := context.Background()
	srv := adtest.Start(t)

	cfg := srv.Config()
	cfg.Replication = adldap.ReplicationConfig{Wait: true, ForceSync: true, Targets: []string{"all"}}

	client, err := adldap.New(ctx, cfg)
	if err != nil {
		t.Fatalf("force_sync must be accepted by this backend: %v", err)
	}
	// Closing matters: a leaked client holds a pooled connection open, and the
	// harness's Stop then blocks on it for the rest of the run.
	defer client.Close()
}
