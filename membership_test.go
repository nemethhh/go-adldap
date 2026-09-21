package adldap_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestMembershipAddReadRemove(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Team", SamAccountName: "Team", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create group: %v", err)
	}
	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("jdoe"), SamAccountName: "jdoe", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	gid := adcore.ByGUID(g.GUID)
	if err := d.Group.AddMembers(ctx, gid, []adcore.Identity{adcore.ByGUID(u.GUID)}); err != nil {
		t.Fatalf("AddMembers: %v", err)
	}

	members, err := d.Group.Members(ctx, gid)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	if len(members) != 1 || members[0].GUID != u.GUID {
		t.Fatalf("Members = %+v, want just the user", members)
	}

	yes, err := d.Group.IsMember(ctx, gid, adcore.ByGUID(u.GUID))
	if err != nil {
		t.Fatalf("IsMember: %v", err)
	}
	if !yes {
		t.Error("IsMember = false for a member")
	}

	if err := d.Group.RemoveMembers(ctx, gid, []adcore.Identity{adcore.ByGUID(u.GUID)}); err != nil {
		t.Fatalf("RemoveMembers: %v", err)
	}
	members, err = d.Group.Members(ctx, gid)
	if err != nil {
		t.Fatalf("Members after removal: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("Members = %+v after removal, want none", members)
	}
}

// Adding a member that is already one is not an error: the desired state
// already holds, and Terraform must converge rather than fail on a re-apply.
func TestAddMembersIsIdempotent(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Idem", SamAccountName: "Idem", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create group: %v", err)
	}
	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("twice"), SamAccountName: "twice", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	gid := adcore.ByGUID(g.GUID)
	ids := []adcore.Identity{adcore.ByGUID(u.GUID)}
	if err := d.Group.AddMembers(ctx, gid, ids); err != nil {
		t.Fatalf("first AddMembers: %v", err)
	}
	if err := d.Group.AddMembers(ctx, gid, ids); err != nil {
		t.Fatalf("second AddMembers must be a no-op, got: %v", err)
	}
	if err := d.Group.RemoveMembers(ctx, gid, ids); err != nil {
		t.Fatalf("RemoveMembers: %v", err)
	}
	if err := d.Group.RemoveMembers(ctx, gid, ids); err != nil {
		t.Fatalf("second RemoveMembers must be a no-op, got: %v", err)
	}
}

// AD returns at most 1500 values of a multi-valued attribute in one read.
// Until ranged retrieval lands, a membership at that boundary must error
// rather than silently return a truncated list — a truncated read would make
// Terraform plan the removal of members that exist.
func TestMembersRefusesToTruncate(t *testing.T) {
	ctx := context.Background()
	srv := adtest.StartMemory(t)
	d := srv.Directory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Huge", SamAccountName: "Huge", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	vals := make([][]byte, 1500)
	for i := range vals {
		vals[i] = []byte("CN=u" + strconv.Itoa(i) + "," + d.DNC)
	}
	entry := srv.Entries()["CN=Huge,"+d.DNC]
	entry["member"] = vals
	srv.Seed("CN=Huge,"+d.DNC, entry)

	_, err = d.Group.Members(ctx, adcore.ByGUID(g.GUID))
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTooManyResults {
		t.Fatalf("want KindTooManyResults at the 1500-value boundary, got %#v", err)
	}
}

// An empty member list is a no-op, not a round trip.
func TestEditMembersWithNoMembersIsANoOp(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)
	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Empty", SamAccountName: "Empty", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Group.AddMembers(ctx, adcore.ByGUID(g.GUID), nil); err != nil {
		t.Errorf("AddMembers(nil) = %v, want nil", err)
	}
}
