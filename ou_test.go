package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// newTestDirectory returns the in-memory directory. It is what the CRUD tests
// use, because gldap — which backs the wire harness — cannot serve ModifyDN,
// and a rename or a move is a ModifyDN. Everything above the go-ldap adapter
// is the real implementation either way; TestOUOverTheWire below covers the
// adapter and the socket for the operations gldap does support.
func newTestDirectory(t *testing.T) adcore.Directory {
	t.Helper()
	return adtest.StartMemory(t).Directory(t)
}

func TestOUCreateReadsBack(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.OU.Create(ctx, adcore.OUSpec{
		Name:        "Staff",
		Container:   d.DNC,
		Description: adcore.String("the staff OU"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.DN != "OU=Staff,"+d.DNC {
		t.Errorf("DN = %q, want %q", created.DN, "OU=Staff,"+d.DNC)
	}
	if created.Container != d.DNC {
		t.Errorf("Container = %q, want %q", created.Container, d.DNC)
	}
	if created.Description != "the staff OU" {
		t.Errorf("Description = %q", created.Description)
	}
	if created.GUID == "" {
		t.Error("Create returned no objectGUID")
	}

	got, err := d.OU.Get(ctx, adcore.ByGUID(created.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if *got != *created {
		t.Errorf("Create returned %+v, Get returns %+v", *created, *got)
	}
}

// A name containing a comma must not reparent the object. Building the RDN by
// concatenation is correct until exactly this input.
func TestOUCreateEscapesTheRDN(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Sales, EMEA", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Container != d.DNC {
		t.Errorf("Container = %q, want %q; the comma in the name reparented the object",
			created.Container, d.DNC)
	}
	if created.Name != "Sales, EMEA" {
		t.Errorf("Name = %q, want the name as given", created.Name)
	}
}

// Rename and move are one ModifyDN, and the objectGUID must survive: deleting
// and recreating would destroy the object's SID and every ACL naming it.
func TestOURenameAndMovePreserveGUID(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	parent, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Parent", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	child, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Before", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create child: %v", err)
	}

	moved, err := d.OU.Update(ctx, adcore.ByGUID(child.GUID), adcore.OUSpec{
		Name:      "After",
		Container: parent.DN,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if moved.GUID != child.GUID {
		t.Fatalf("objectGUID changed: %q -> %q; the object was replaced", child.GUID, moved.GUID)
	}
	if moved.DN != "OU=After,"+parent.DN {
		t.Errorf("DN = %q, want %q", moved.DN, "OU=After,"+parent.DN)
	}
}

func TestOUUpdateDescriptionOnly(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Desc", Container: d.DNC, Description: adcore.String("before")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := d.OU.Update(ctx, adcore.ByGUID(ou.GUID), adcore.OUSpec{
		Name: "Desc", Container: d.DNC, Description: adcore.String("after"),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Description != "after" {
		t.Errorf("Description = %q, want %q", updated.Description, "after")
	}
	if updated.DN != ou.DN {
		t.Errorf("DN changed on an attribute-only update: %q -> %q", ou.DN, updated.DN)
	}
}

// A pointer to the empty string clears the attribute; AD has no empty value.
func TestOUUpdateClearsDescription(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Clear", Container: d.DNC, Description: adcore.String("gone soon")})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := d.OU.Update(ctx, adcore.ByGUID(ou.GUID), adcore.OUSpec{
		Name: "Clear", Container: d.DNC, Description: adcore.String(""),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Description != "" {
		t.Errorf("Description = %q, want it cleared", updated.Description)
	}
}

func TestOUDeleteIsVerified(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Doomed", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.OU.Delete(ctx, adcore.ByGUID(ou.GUID), adcore.DeleteOptions{Unprotect: true}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.OU.Get(ctx, adcore.ByGUID(ou.GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("the OU is still readable after Delete: %v", err)
	}
}

// Recursive deletion is deliberately not offered: the error names the child
// count so an operator can see what they would have destroyed.
func TestOUDeleteRefusesNonEmpty(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	parent, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Full", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Child", Container: parent.DN}); err != nil {
		t.Fatalf("Create child: %v", err)
	}

	err = d.OU.Delete(ctx, adcore.ByGUID(parent.GUID), adcore.DeleteOptions{Unprotect: true})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindConstraint {
		t.Fatalf("want KindConstraint, got %#v", err)
	}
}

// A not-found during Delete is success: the desired state already holds.
func TestOUDeleteOfAMissingObjectSucceeds(t *testing.T) {
	d := newTestDirectory(t)
	err := d.OU.Delete(context.Background(),
		adcore.ByGUID("00000000-0000-0000-0000-000000000000"), adcore.DeleteOptions{})
	if err != nil {
		t.Fatalf("Delete of a missing OU = %v, want nil", err)
	}
}

// The wire harness covers what gldap can serve: a create, a read-back and a
// delete over real LDAP on a real socket, which is what proves the go-ldap
// adapter encodes and decodes correctly.
func TestOUOverTheWire(t *testing.T) {
	ctx := context.Background()
	d := adtest.StartWire(t)

	created, err := d.OU.Create(ctx, adcore.OUSpec{
		Name: "Wire", Container: d.DNC, Description: adcore.String("over a socket"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.GUID == "" {
		t.Fatal("Create returned no objectGUID; the adapter dropped the binary attribute")
	}

	got, err := d.OU.Get(ctx, adcore.ByGUID(created.GUID))
	if err != nil {
		t.Fatalf("Get by GUID over the wire: %v", err)
	}
	if got.Description != "over a socket" {
		t.Errorf("Description = %q", got.Description)
	}

	if err := d.OU.Delete(ctx, adcore.ByGUID(created.GUID), adcore.DeleteOptions{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// Protection is a Deny ACE on the object's security descriptor. The provider
// defaults protected_from_accidental_deletion to true, so an OU create that
// accepted the field and ignored it failed the apply with "inconsistent result
// after apply" — which named neither the field nor the reason. Found on the
// lab, where it blocked every non-skipped acceptance test.
func TestOUProtectionRoundTrips(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	on, err := d.OU.Create(ctx, adcore.OUSpec{
		Name: "Guarded", Container: d.DNC, Protected: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Create protected: %v", err)
	}
	if !on.Protected {
		t.Error("Create returned Protected=false for a protected OU")
	}
	got, err := d.OU.Get(ctx, adcore.ByGUID(on.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Protected {
		t.Error("Get returned Protected=false for a protected OU")
	}

	off, err := d.OU.Update(ctx, adcore.ByGUID(on.GUID), adcore.OUSpec{
		Name: "Guarded", Container: d.DNC, Protected: adcore.Bool(false),
	})
	if err != nil {
		t.Fatalf("Update lifting protection: %v", err)
	}
	if off.Protected {
		t.Error("protection survived an update that cleared it")
	}
}

func TestOUCreatedUnprotectedByDefault(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)
	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Plain", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if ou.Protected {
		t.Error("an OU created with no Protected field reports protected")
	}
}

// A protected OU cannot be moved while the Deny is in place, because it covers
// DeleteTree and AD checks that on a re-parent. Update lifts it and puts it
// back, so a rename of a protected OU has to end protected.
func TestOUMoveKeepsProtection(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	parent, err := d.OU.Create(ctx, adcore.OUSpec{Name: "NewParent", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}
	child, err := d.OU.Create(ctx, adcore.OUSpec{
		Name: "Movable", Container: d.DNC, Protected: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Create child: %v", err)
	}

	moved, err := d.OU.Update(ctx, adcore.ByGUID(child.GUID), adcore.OUSpec{
		Name: "Moved", Container: parent.DN, Protected: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Update moving a protected OU: %v", err)
	}
	if moved.GUID != child.GUID {
		t.Fatalf("objectGUID changed: %q -> %q", child.GUID, moved.GUID)
	}
	if !moved.Protected {
		t.Error("protection was lifted for the move and never restored")
	}
	if moved.DN != "OU=Moved,"+parent.DN {
		t.Errorf("DN = %q", moved.DN)
	}
}

// Delete with Unprotect lifts the Deny first; without it the directory's own
// refusal stands.
func TestOUDeleteUnprotectsFirst(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{
		Name: "Doomed2", Container: d.DNC, Protected: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.OU.Delete(ctx, adcore.ByGUID(ou.GUID), adcore.DeleteOptions{Unprotect: true}); err != nil {
		t.Fatalf("Delete with Unprotect: %v", err)
	}
	if _, err := d.OU.Get(ctx, adcore.ByGUID(ou.GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("the OU is still readable: %v", err)
	}
}
