package adldap_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

const pastOnePage = adtest.MaxPageSize + 200

func seededGUID(i int) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[8:12], uint32(i+1))
	b[15] = 0x7e
	return b
}

func wireDirectory(t *testing.T, srv *adtest.Server) adcore.Directory {
	t.Helper()
	client, err := adldap.New(context.Background(), srv.Config())
	if err != nil {
		t.Fatalf("adldap.New: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client.Directory()
}

func TestSearchPastTheServerPageSizeOverTheWire(t *testing.T) {
	srv := adtest.Start(t)
	for i := 0; i < pastOnePage; i++ {
		name := fmt.Sprintf("Paged%04d", i)
		srv.Seed("OU="+name+","+adtest.DNC, map[string][][]byte{
			"objectClass": {[]byte("top"), []byte("organizationalUnit")},
			"ou":          {[]byte(name)},
			"name":        {[]byte(name)},
			"objectGUID":  {seededGUID(i)},
		})
	}
	d := wireDirectory(t, srv)

	got, err := d.OU.Search(context.Background(), adcore.Query{SearchBase: adtest.DNC, SizeLimit: 5000})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != pastOnePage {
		t.Fatalf("Search returned %d OUs, want %d", len(got), pastOnePage)
	}
}

func TestMembersPastTheServerPageSizeOverTheWire(t *testing.T) {
	srv := adtest.Start(t)
	members := make([][]byte, 0, pastOnePage)
	for i := 0; i < pastOnePage; i++ {
		name := fmt.Sprintf("m%04d", i)
		dn := "CN=" + name + "," + adtest.DNC
		srv.Seed(dn, map[string][][]byte{
			"distinguishedName": {[]byte(dn)},
			"objectClass":       {[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("user")},
			"cn":                {[]byte(name)},
			"sAMAccountName":    {[]byte(name)},
			"objectGUID":        {seededGUID(i)},
		})
		members = append(members, []byte(dn))
	}
	groupGUID := seededGUID(pastOnePage)
	srv.Seed("CN=Big,"+adtest.DNC, map[string][][]byte{
		"objectClass":    {[]byte("top"), []byte("group")},
		"cn":             {[]byte("Big")},
		"sAMAccountName": {[]byte("Big")},
		"objectGUID":     {groupGUID},
		"member":         members,
	})
	d := wireDirectory(t, srv)

	got, err := d.Group.Members(context.Background(), adcore.ByDN("CN=Big,"+adtest.DNC))
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(got) != pastOnePage {
		t.Fatalf("Members returned %d, want %d", len(got), pastOnePage)
	}
}

func TestMembersRecursivePastOneThousand(t *testing.T) {
	ctx := context.Background()
	srv := adtest.StartMemory(t)
	d := srv.Directory(t)
	group, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Big", SamAccountName: "Big", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create group: %v", err)
	}
	for i := 0; i < pastOnePage; i++ {
		name := fmt.Sprintf("m%04d", i)
		srv.Seed("CN="+name+","+d.DNC, map[string][][]byte{
			"objectClass":    {[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("user")},
			"cn":             {[]byte(name)},
			"sAMAccountName": {[]byte(name)},
			"objectGUID":     {seededGUID(i)},
			"memberOf":       {[]byte(group.DN)},
		})
	}

	got, err := d.Group.MembersRecursive(ctx, adcore.ByGUID(group.GUID))
	if err != nil {
		t.Fatalf("MembersRecursive: %v", err)
	}
	if len(got) != pastOnePage {
		t.Fatalf("MembersRecursive returned %d, want %d", len(got), pastOnePage)
	}
}
