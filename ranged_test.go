package adldap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// A group past the domain controller's MaxValRange must read completely, not
// error and not truncate. Truncation is the worse failure: Terraform reads a
// short list and plans the removal of members that exist.
func TestGroupMembersPastTheRangeLimit(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	const n = 2300
	members := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		dn := fmt.Sprintf("CN=u%04d,%s", i, d.DNC)
		m.Seed(dn, map[string][][]byte{
			"objectClass":       {[]byte("user")},
			"objectGUID":        {testGUIDFor(i)},
			"distinguishedName": {[]byte(dn)},
			"name":              {[]byte(fmt.Sprintf("u%04d", i))},
		})
		members = append(members, []byte(dn))
	}
	gdn := "CN=big," + d.DNC
	m.Seed(gdn, map[string][][]byte{
		"objectClass":       {[]byte("group")},
		"objectGUID":        {testGUIDFor(9999)},
		"distinguishedName": {[]byte(gdn)},
		"name":              {[]byte("big")},
		"member":            members,
	})
	m.RangeLimit(1500) // make the harness behave like a DC

	got, err := d.Group.Members(ctx, adcore.ByDN(gdn))
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != n {
		t.Errorf("read %d members, want %d", len(got), n)
	}
}

// The last page can be exactly the page size, so the terminator must be the
// "*" the server puts in the response range, never a short page.
func TestGroupMembersExactlyOnAPageBoundary(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	const n = 3000 // exactly two full pages
	members := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		dn := fmt.Sprintf("CN=b%04d,%s", i, d.DNC)
		m.Seed(dn, map[string][][]byte{
			"objectClass":       {[]byte("user")},
			"objectGUID":        {testGUIDFor(i)},
			"distinguishedName": {[]byte(dn)},
			"name":              {[]byte(fmt.Sprintf("b%04d", i))},
		})
		members = append(members, []byte(dn))
	}
	gdn := "CN=exact," + d.DNC
	m.Seed(gdn, map[string][][]byte{
		"objectClass":       {[]byte("group")},
		"objectGUID":        {testGUIDFor(8888)},
		"distinguishedName": {[]byte(gdn)},
		"name":              {[]byte("exact")},
		"member":            members,
	})
	m.RangeLimit(1500)

	got, err := d.Group.Members(ctx, adcore.ByDN(gdn))
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != n {
		t.Errorf("read %d members, want %d — a full final page must not be mistaken for the end", len(got), n)
	}
}

// testGUIDFor returns a distinct well-formed 16-byte GUID per index.
func testGUIDFor(i int) []byte {
	b := make([]byte, 16)
	b[0], b[1] = byte(i), byte(i>>8)
	b[15] = 0x42
	return b
}
