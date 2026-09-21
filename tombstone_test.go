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
