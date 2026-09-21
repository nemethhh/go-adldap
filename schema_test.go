package adldap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestSchemaResolveAttributeAndClass(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	// schemaIDGUID is an octet string.
	m.Seed("CN=Password-Last-Set,CN=Schema,CN=Configuration,"+d.DNC, map[string][][]byte{
		"objectClass":     {[]byte("attributeSchema")},
		"lDAPDisplayName": {[]byte("pwdLastSet")},
		"schemaIDGUID":    {{0x0e, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}},
	})
	m.Seed("CN=User,CN=Schema,CN=Configuration,"+d.DNC, map[string][][]byte{
		"objectClass":     {[]byte("classSchema")},
		"lDAPDisplayName": {[]byte("user")},
		"schemaIDGUID":    {{0xba, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2}},
	})

	refs := []adcore.SchemaRef{
		{Kind: adcore.RefAttribute, Name: "pwdLastSet"},
		{Kind: adcore.RefClass, Name: "user"},
	}
	got, err := d.Schema.Resolve(ctx, refs)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got[refs[0]] != "bf967a0e-0de6-11d0-a285-00aa003049e2" {
		t.Errorf("pwdLastSet = %q", got[refs[0]])
	}
	if got[refs[1]] != "bf967aba-0de6-11d0-a285-00aa003049e2" {
		t.Errorf("user = %q", got[refs[1]])
	}
}

// rightsGuid is a STRING attribute, unlike schemaIDGUID. Formatting its bytes
// as a binary GUID produces a well-formed value that matches nothing, and the
// resulting ACE grants a right nobody asked for.
func TestSchemaResolveExtendedRightReadsRightsGuidAsAString(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	m.Seed("CN=Reset Password,CN=Extended-Rights,CN=Configuration,"+d.DNC, map[string][][]byte{
		"objectClass": {[]byte("controlAccessRight")},
		"displayName": {[]byte("Reset Password")},
		"rightsGuid":  {[]byte("00299570-246d-11d0-a768-00aa006e0529")},
	})

	ref := adcore.SchemaRef{Kind: adcore.RefExtendedRight, Name: "Reset Password"}
	got, err := d.Schema.Resolve(ctx, []adcore.SchemaRef{ref})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got[ref] != "00299570-246d-11d0-a768-00aa006e0529" {
		t.Errorf("Reset Password = %q, want the rightsGuid verbatim", got[ref])
	}
}

// A GUID needs no search. The provider accepts either form, and resolving one
// through the directory is a wasted round trip per ACE.
func TestSchemaResolvePassesAGUIDThrough(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	ref := adcore.SchemaRef{Kind: adcore.RefAttribute, Name: "bf967a0e-0de6-11d0-a285-00aa003049e2"}
	got, err := d.Schema.Resolve(ctx, []adcore.SchemaRef{ref})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got[ref] != "bf967a0e-0de6-11d0-a285-00aa003049e2" {
		t.Errorf("got %q, want the GUID unchanged", got[ref])
	}
}

// An unresolvable name is an error naming it. Omitting it from the map would
// leave the caller building an ACE with an empty object type, which is "all
// properties" — very much more than was asked for.
func TestSchemaResolveUnknownNameIsAnError(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	_, err := d.Schema.Resolve(ctx, []adcore.SchemaRef{
		{Kind: adcore.RefAttribute, Name: "notAnAttribute"},
	})
	if err == nil {
		t.Fatal("want an error for an unresolvable name, got nil")
	}
	if !strings.Contains(err.Error(), "notAnAttribute") {
		t.Errorf("error %q does not name the unresolvable reference", err)
	}
}
