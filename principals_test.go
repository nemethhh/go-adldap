package adldap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
)

func TestComputerRBCDRoundTrips(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	front, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "WEB01", SamAccountName: "WEB01", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create WEB01: %v", err)
	}
	back, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SQL01", SamAccountName: "SQL01", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create SQL01: %v", err)
	}

	// WEB01 may impersonate to SQL01, so the ACE goes on SQL01.
	updated, err := d.Computer.Update(ctx, adcore.ByGUID(back.GUID), adcore.ComputerSpec{
		Name: "SQL01", SamAccountName: "SQL01", Container: d.DNC,
		PrincipalsAllowed: []adcore.Identity{adcore.ByGUID(front.GUID)},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(updated.PrincipalsAllowed) != 1 {
		t.Fatalf("PrincipalsAllowed = %v, want one entry", updated.PrincipalsAllowed)
	}
	// The model carries object GUIDs, not SIDs and not DNs — that is what the
	// provider stores and what the PowerShell backend emits.
	if updated.PrincipalsAllowed[0] != front.GUID {
		t.Errorf("PrincipalsAllowed[0] = %q, want %q", updated.PrincipalsAllowed[0], front.GUID)
	}

	// nil leaves it alone.
	same, err := d.Computer.Update(ctx, adcore.ByGUID(back.GUID), adcore.ComputerSpec{
		Name: "SQL01", SamAccountName: "SQL01", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Update (nil principals): %v", err)
	}
	if len(same.PrincipalsAllowed) != 1 {
		t.Errorf("a nil PrincipalsAllowed cleared RBCD; want it left alone")
	}

	// An empty non-nil slice clears it. This must produce a present-but-empty
	// DACL, not an absent attribute — the difference between "nobody may
	// impersonate here" and whatever AD's default is.
	cleared, err := d.Computer.Update(ctx, adcore.ByGUID(back.GUID), adcore.ComputerSpec{
		Name: "SQL01", SamAccountName: "SQL01", Container: d.DNC,
		PrincipalsAllowed: []adcore.Identity{},
	})
	if err != nil {
		t.Fatalf("Update (empty principals): %v", err)
	}
	if len(cleared.PrincipalsAllowed) != 0 {
		t.Errorf("PrincipalsAllowed = %v, want empty", cleared.PrincipalsAllowed)
	}
}

func TestComputerRBCDSetAtCreate(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	front, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "WEB02", SamAccountName: "WEB02", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create WEB02: %v", err)
	}
	back, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SQL02", SamAccountName: "SQL02", Container: d.DNC,
		PrincipalsAllowed: []adcore.Identity{adcore.ByGUID(front.GUID)},
	})
	if err != nil {
		t.Fatalf("Create SQL02: %v", err)
	}
	if len(back.PrincipalsAllowed) != 1 || back.PrincipalsAllowed[0] != front.GUID {
		t.Errorf("PrincipalsAllowed = %v, want [%s]", back.PrincipalsAllowed, front.GUID)
	}
}

// A principal that does not exist must fail by name. Writing a descriptor with
// the principal silently missing is the failure mode that costs an afternoon:
// the apply succeeds, the delegation does not work, and nothing says why.
func TestComputerRBCDUnknownPrincipalIsNamed(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	c, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SQL03", SamAccountName: "SQL03", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = d.Computer.Update(ctx, adcore.ByGUID(c.GUID), adcore.ComputerSpec{
		Name: "SQL03", SamAccountName: "SQL03", Container: d.DNC,
		PrincipalsAllowed: []adcore.Identity{adcore.BySAM("nosuchthing")},
	})
	if err == nil {
		t.Fatal("want an error naming the missing principal, got nil")
	}
	if !strings.Contains(err.Error(), "nosuchthing") {
		t.Errorf("error %q does not name the missing principal", err)
	}
}
