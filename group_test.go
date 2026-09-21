package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
)

// groupType carries scope and category in one field. Changing the scope must
// leave the category alone, and vice versa.
func TestGroupScopeAndCategoryRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	for _, tc := range []struct {
		name     string
		scope    adcore.GroupScope
		category adcore.GroupCategory
	}{
		{"GlobalSec", adcore.GroupScopeGlobal, adcore.GroupCategorySecurity},
		{"LocalDist", adcore.GroupScopeDomainLocal, adcore.GroupCategoryDistribution},
		{"UniSec", adcore.GroupScopeUniversal, adcore.GroupCategorySecurity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := d.Group.Create(ctx, adcore.GroupSpec{
				Name:           tc.name,
				SamAccountName: tc.name,
				Container:      d.DNC,
				Scope:          tc.scope,
				Category:       tc.category,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if g.Scope != tc.scope {
				t.Errorf("Scope = %v, want %v", g.Scope, tc.scope)
			}
			if g.Category != tc.category {
				t.Errorf("Category = %v, want %v", g.Category, tc.category)
			}
		})
	}
}

// Changing only the scope must not flip the category, which shares the field.
func TestGroupScopeChangeKeepsCategory(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Movers", SamAccountName: "Movers", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategoryDistribution,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := d.Group.Update(ctx, adcore.ByGUID(g.GUID), adcore.GroupSpec{
		Name: "Movers", SamAccountName: "Movers", Container: d.DNC,
		Scope: adcore.GroupScopeUniversal, Category: adcore.GroupCategoryDistribution,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Scope != adcore.GroupScopeUniversal {
		t.Errorf("Scope = %v, want universal", updated.Scope)
	}
	if updated.Category != adcore.GroupCategoryDistribution {
		t.Errorf("Category = %v after a scope-only change, want distribution", updated.Category)
	}
}

// The mirror of the above: a category change must not disturb the scope.
func TestGroupCategoryChangeKeepsScope(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Flip", SamAccountName: "Flip", Container: d.DNC,
		Scope: adcore.GroupScopeDomainLocal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := d.Group.Update(ctx, adcore.ByGUID(g.GUID), adcore.GroupSpec{
		Name: "Flip", SamAccountName: "Flip", Container: d.DNC,
		Scope: adcore.GroupScopeDomainLocal, Category: adcore.GroupCategoryDistribution,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Scope != adcore.GroupScopeDomainLocal {
		t.Errorf("Scope = %v after a category-only change, want domainlocal", updated.Scope)
	}
	if updated.Category != adcore.GroupCategoryDistribution {
		t.Errorf("Category = %v, want distribution", updated.Category)
	}
}

func TestGroupDeleteIsVerified(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Gone", SamAccountName: "Gone", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.Group.Delete(ctx, adcore.ByGUID(g.GUID)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.Group.Get(ctx, adcore.ByGUID(g.GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("the group is still readable after Delete: %v", err)
	}
}

// A group can be found by sAMAccountName, which is how the provider imports one.
func TestGroupGetBySAM(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "BySam", SamAccountName: "bysam", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := d.Group.Get(ctx, adcore.BySAM("bysam"))
	if err != nil {
		t.Fatalf("Get by sAMAccountName: %v", err)
	}
	if got.GUID != created.GUID {
		t.Errorf("GUID = %q, want %q", got.GUID, created.GUID)
	}
}
