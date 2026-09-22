package adldap_test

import (
	"context"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// A delegation template is expanded by go-adcore, resolved by this backend's
// Schema, and written by its ACL. Each half has its own test; this is the
// seam between them, which is where a mismatch between the friendly-name
// vocabulary and the schema's actual names would hide.
func TestDelegationTemplateAppliesOverLDAP(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	seedSchema(t, m, d.DNC)

	ou, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Helpdesk", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create OU: %v", err)
	}
	user, err := d.User.Create(ctx, adcore.UserSpec{SamAccountName: "hdlead", Container: d.DNC})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	var deleg adcore.Delegation
	specs, err := deleg.Template(adcore.TaskResetUserPasswords)
	if err != nil {
		t.Fatalf("Template: %v", err)
	}

	// Resolve every friendly name the template emitted, in one batch.
	var refs []adcore.SchemaRef
	for _, s := range specs {
		if s.ObjectType != "" {
			refs = append(refs, adcore.SchemaRef{Kind: refKindFor(s), Name: s.ObjectType})
		}
		if s.ObjectClass != "" {
			refs = append(refs, adcore.SchemaRef{Kind: adcore.RefClass, Name: s.ObjectClass})
		}
	}
	resolved, err := d.Schema.Resolve(ctx, refs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var aces []adcore.ACE
	for _, s := range specs {
		a := adcore.ACE{Trustee: user.SID, Type: s.Type, Rights: s.Rights, Inheritance: s.Scope}
		if s.ObjectType != "" {
			a.ObjectType = resolved[adcore.SchemaRef{Kind: refKindFor(s), Name: s.ObjectType}]
		}
		if s.ObjectClass != "" {
			a.InheritedObjectType = resolved[adcore.SchemaRef{Kind: adcore.RefClass, Name: s.ObjectClass}]
		}
		aces = append(aces, a)
	}

	if err := d.ACL.Grant(ctx, adcore.ByGUID(ou.GUID), aces); err != nil {
		t.Fatalf("Grant: %v", err)
	}

	got, err := d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, want := range aces {
		if !hasACE(got, want) {
			t.Errorf("the template's ACE %+v is not on the OU", want)
		}
	}

	// And it comes back off cleanly, which is what a destroy depends on.
	if err := d.ACL.Revoke(ctx, adcore.ByGUID(ou.GUID), aces); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, err = d.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
	if err != nil {
		t.Fatalf("Get after Revoke: %v", err)
	}
	for _, want := range aces {
		if hasACE(got, want) {
			t.Errorf("the template's ACE %+v survived the revoke", want)
		}
	}
}

// refKindFor says which partition a spec's ObjectType is resolved against. An
// ExtendedRight names a controlAccessRight under Extended-Rights; anything
// else names an attribute in the schema. Getting this wrong resolves to
// nothing, and the ACE is then written with no object type at all — which
// means every property.
func refKindFor(s adcore.ACESpec) adcore.SchemaRefKind {
	for _, r := range s.Rights {
		if r == "ExtendedRight" {
			return adcore.RefExtendedRight
		}
	}
	return adcore.RefAttribute
}

// seedSchema plants the schema objects the reset_user_passwords template
// names: the Reset Password extended right, the pwdLastSet attribute and the
// user class.
func seedSchema(t *testing.T, m *adtest.MemServer, dnc string) {
	t.Helper()
	m.Seed("CN=Reset Password,CN=Extended-Rights,CN=Configuration,"+dnc, map[string][][]byte{
		"objectClass": {[]byte("controlAccessRight")},
		"displayName": {[]byte("Reset Password")},
		"rightsGuid":  {[]byte("00299570-246d-11d0-a768-00aa006e0529")},
	})
	m.Seed("CN=Password-Last-Set,CN=Schema,CN=Configuration,"+dnc, map[string][][]byte{
		"objectClass":     {[]byte("attributeSchema")},
		"lDAPDisplayName": {[]byte("pwdLastSet")},
		"schemaIDGUID":    {{0x0e, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}},
	})
	m.Seed("CN=User,CN=Schema,CN=Configuration,"+dnc, map[string][][]byte{
		"objectClass":     {[]byte("classSchema")},
		"lDAPDisplayName": {[]byte("user")},
		"schemaIDGUID":    {{0xba, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}},
	})
}
