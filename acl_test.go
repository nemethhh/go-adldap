package adldap_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// mustTestGUID is any well-formed objectGUID, for an entry seeded directly
// rather than created through the client.
func mustTestGUID() []byte {
	return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
}

func TestACLGetReadsExplicitEntries(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}

	got, err := d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("ACL.Get: %v", err)
	}
	// A freshly created OU carries AD's own protection Deny, so the read is
	// not expected to be empty — it is expected to decode.
	for _, a := range got {
		if a.Trustee == "" {
			t.Error("an ACE decoded with no trustee SID")
		}
		if a.Type != adcore.ACEAllow && a.Type != adcore.ACEDeny {
			t.Errorf("ACE type = %q, want Allow or Deny", a.Type)
		}
		// The all-zero GUID is "" here. Emitting it verbatim would be a
		// permanent diff against the PowerShell backend, which normalises it.
		if a.ObjectType == "00000000-0000-0000-0000-000000000000" {
			t.Error("the all-zero object GUID must read back as an empty string")
		}
	}
}

func TestACLGetOnAMissingObject(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	_, err := d.ACL.Get(ctx, adcore.ByDN("OU=NoSuchThing,"+d.DNC))
	if !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("ACL.Get on a missing object = %v, want ErrNotFound", err)
	}
}

// A descriptor AD returns empty — which is what a caller without
// SeSecurityPrivilege gets for an unmasked read — must be an error naming the
// cause, not an empty ACL. An empty ACL reads as "no delegations exist" and
// Terraform plans to create every one of them.
func TestACLGetRefusesAnEmptyDescriptor(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	m.Seed("OU=Blind,"+d.DNC, map[string][][]byte{
		"objectClass":       {[]byte("organizationalUnit")},
		"objectGUID":        {mustTestGUID()},
		"distinguishedName": {[]byte("OU=Blind," + d.DNC)},
		"name":              {[]byte("Blind")},
		// nTSecurityDescriptor deliberately absent.
	})

	_, err := d.ACL.Get(ctx, adcore.ByDN("OU=Blind,"+d.DNC))
	if err == nil {
		t.Fatal("want an error for an unreadable descriptor, got nil and an empty ACL")
	}
	if !strings.Contains(err.Error(), "nTSecurityDescriptor") {
		t.Errorf("error %q does not name the attribute that could not be read", err)
	}
}

func TestACLGrantAndRevokeRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated2", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	user, err := d.User.Create(ctx, adcore.UserSpec{
		SamAccountName: "helpdesk", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	want := adcore.ACE{
		Trustee:             user.SID,
		Type:                adcore.ACEAllow,
		Rights:              []adcore.Right{"ReadProperty", "WriteProperty"},
		ObjectType:          "bf967a0e-0de6-11d0-a285-00aa003049e2", // pwdLastSet
		InheritedObjectType: "bf967aba-0de6-11d0-a285-00aa003049e2", // user class
		Inheritance:         adcore.InheritanceDescendants,
	}

	if err := d.ACL.Grant(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{want}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	got, err := d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hasACE(got, want) {
		t.Fatalf("the granted ACE is not in %v", got)
	}

	if err := d.ACL.Revoke(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{want}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err = d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	if hasACE(got, want) {
		t.Error("the ACE survived the revoke")
	}
}

// hasACE compares on the canonical key, which is what drift detection uses.
// Comparing field by field here would let the test pass on a representation
// the provider would then report as drifted.
func hasACE(list []adcore.ACE, want adcore.ACE) bool {
	key := adcore.CanonicalACEKey(want)
	for _, a := range list {
		if adcore.CanonicalACEKey(a) == key {
			return true
		}
	}
	return false
}

func TestACLGrantIsIdempotent(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated3", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	user, err := d.User.Create(ctx, adcore.UserSpec{SamAccountName: "hd2", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	ace := adcore.ACE{
		Trustee: user.SID, Type: adcore.ACEAllow,
		Rights: []adcore.Right{"GenericAll"}, Inheritance: adcore.InheritanceDescendants,
	}
	for i := 0; i < 2; i++ {
		if err := d.ACL.Grant(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{ace}); err != nil {
			t.Fatalf("Grant %d: %v", i, err)
		}
	}

	got, err := d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	key := adcore.CanonicalACEKey(ace)
	n := 0
	for _, a := range got {
		if adcore.CanonicalACEKey(a) == key {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the ACE appears %d times, want 1", n)
	}
}

// Rights order and case must not matter. If they did, a user reordering the
// list in configuration would get a second ACE rather than no change, and a
// revoke written in a different order would silently match nothing.
func TestACLRevokeMatchesRegardlessOfRightsOrderAndCase(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated4", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	user, err := d.User.Create(ctx, adcore.UserSpec{SamAccountName: "hd3", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	if err := d.ACL.Grant(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{{
		Trustee: user.SID, Type: adcore.ACEAllow,
		Rights: []adcore.Right{"ReadProperty", "WriteProperty"}, Inheritance: adcore.InheritanceThis,
	}}); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	if err := d.ACL.Revoke(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{{
		Trustee: user.SID, Type: adcore.ACEAllow,
		Rights: []adcore.Right{"writeproperty", "readproperty"}, Inheritance: adcore.InheritanceThis,
	}}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	got, err := d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, a := range got {
		if a.Trustee == user.SID && !a.Inherited {
			t.Errorf("an explicit ACE for the trustee survived: %+v", a)
		}
	}
}

func TestACLGrantRejectsAnUnknownRight(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated5", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	err = d.ACL.Grant(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{{
		Trustee: "S-1-5-21-1-2-3-1104", Type: adcore.ACEAllow,
		Rights: []adcore.Right{"MakeMeAdmin"},
	}})
	if err == nil {
		t.Fatal("want an error for an unknown right, got nil")
	}
	if !strings.Contains(err.Error(), "MakeMeAdmin") {
		t.Errorf("error %q does not name the offending right", err)
	}
}

// Revoking something that is not there is not an error, and must not write.
// Terraform destroys resources it has already lost track of, and a hard
// failure there strands the state.
func TestACLRevokeOfSomethingAbsentIsNotAnError(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Delegated6", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	if err := d.ACL.Revoke(ctx, adcore.ByGUID(ou.GUID), []adcore.ACE{{
		Trustee: "S-1-5-21-1-2-3-9999", Type: adcore.ACEAllow,
		Rights: []adcore.Right{"GenericAll"},
	}}); err != nil {
		t.Errorf("Revoke of an absent ACE = %v, want nil", err)
	}
}
