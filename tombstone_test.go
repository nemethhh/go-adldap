package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// A create refused because a deleted object still holds the name must say so,
// and name the tombstone — otherwise the operator sees "already exists" for an
// object they cannot find.
func TestAlreadyExistsIsTracedToATombstone(t *testing.T) {
	ctx := context.Background()
	srv := adtest.StartMemory(t)
	d := srv.Directory(t)

	srv.Seed(`CN=Gone\0ADEL:abc,CN=Deleted Objects,`+d.DNC, map[string][][]byte{
		"objectClass":     {[]byte("top"), []byte("organizationalUnit")},
		"objectGUID":      {make([]byte, 16)},
		"isDeleted":       {[]byte("TRUE")},
		"name":            {[]byte("Gone")},
		"lastKnownParent": {[]byte(d.DNC)},
	})
	srv.Seed("OU=Gone,"+d.DNC, map[string][][]byte{
		"objectClass": {[]byte("top"), []byte("organizationalUnit")},
		"objectGUID":  {make([]byte, 16)},
		"name":        {[]byte("Gone")},
	})

	_, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Gone", Container: d.DNC})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindAlreadyExists {
		t.Fatalf("want KindAlreadyExists, got %#v", err)
	}
	if !e.Tombstoned {
		t.Error("Tombstoned = false; the probe should have found the deleted object")
	}
	if e.Target == "" {
		t.Error("Target is empty; it should name the tombstone's DN")
	}
}

// Without the show-deleted control a tombstone is invisible, so an ordinary
// already-exists must not be annotated. This is what proves the control is
// actually being sent rather than the probe matching by luck.
func TestAlreadyExistsWithoutATombstoneIsNotAnnotated(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Live", Container: d.DNC}); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Live", Container: d.DNC})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindAlreadyExists {
		t.Fatalf("want KindAlreadyExists, got %#v", err)
	}
	if e.Tombstoned {
		t.Error("Tombstoned = true for a live object; nothing was deleted")
	}
}

func TestAlreadyExistsOnALiveObjectNamesItsDN(t *testing.T) {
	cases := []struct {
		name   string
		rdn    string
		create func(context.Context, adcore.Directory) error
	}{
		{"ou", "OU=Live", func(ctx context.Context, d adcore.Directory) error {
			_, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Live", Container: d.DNC})
			return err
		}},
		{"group", "CN=Live", func(ctx context.Context, d adcore.Directory) error {
			_, err := d.Group.Create(ctx, adcore.GroupSpec{
				Name: "Live", SamAccountName: "Live", Container: d.DNC,
				Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
			})
			return err
		}},
		{"user", "CN=Live", func(ctx context.Context, d adcore.Directory) error {
			_, err := d.User.Create(ctx, adcore.UserSpec{
				Name: adcore.String("Live"), SamAccountName: "Live", Container: d.DNC,
			})
			return err
		}},
		{"computer", "CN=LIVE01", func(ctx context.Context, d adcore.Directory) error {
			_, err := d.Computer.Create(ctx, adcore.ComputerSpec{
				Name: "LIVE01", SamAccountName: "LIVE01", Container: d.DNC,
			})
			return err
		}},
		{"gmsa", "CN=svc-live", func(ctx context.Context, d adcore.Directory) error {
			_, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
				Name: "svc-live", SamAccountName: "svc-live", Container: d.DNC,
				DNSHostName: adcore.String("svc-live.corp.local"),
			})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			d := newTestDirectory(t)

			if err := tc.create(ctx, d); err != nil {
				t.Fatalf("first Create: %v", err)
			}
			err := tc.create(ctx, d)
			var e *adcore.Error
			if !errors.As(err, &e) || e.Kind != adcore.KindAlreadyExists {
				t.Fatalf("want KindAlreadyExists, got %#v", err)
			}
			if want := tc.rdn + "," + d.DNC; e.Target != want {
				t.Errorf("Target = %q, want %q", e.Target, want)
			}
		})
	}
}
