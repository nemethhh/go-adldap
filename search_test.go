package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestSearchErrorsRatherThanTruncating(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)
	for _, n := range []string{"A", "B", "C"} {
		if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: n, Container: d.DNC}); err != nil {
			t.Fatalf("Create %s: %v", n, err)
		}
	}

	_, err := d.OU.Search(ctx, adcore.Query{SearchBase: d.DNC, SizeLimit: 2})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTooManyResults {
		t.Fatalf("want KindTooManyResults, got %#v", err)
	}
}

func TestSearchWithinLimitSucceeds(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)
	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Only", Container: d.DNC}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := d.OU.Search(ctx, adcore.Query{SearchBase: d.DNC, SizeLimit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if got[0].Name != "Only" {
		t.Errorf("Name = %q, want %q", got[0].Name, "Only")
	}
}

// An identity matching nothing is not-found; the search itself succeeded.
func TestGetOfAMissingObjectIsNotFound(t *testing.T) {
	d := newTestDirectory(t)
	_, err := d.OU.Get(context.Background(), adcore.ByGUID("00000000-0000-0000-0000-00000000dead"))
	if !errors.Is(err, adcore.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %#v", err)
	}
}

// A search over the wire exercises the adapter's filter encoding and its
// binary read-back, which the in-memory conn cannot.
func TestSearchOverTheWire(t *testing.T) {
	ctx := context.Background()
	d := adtest.StartWire(t)
	if _, err := d.OU.Create(ctx, adcore.OUSpec{Name: "Findable", Container: d.DNC}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := d.OU.Search(ctx, adcore.Query{SearchBase: d.DNC, SizeLimit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Findable" {
		t.Fatalf("Search returned %+v", got)
	}
}

// resolveDN looks an object up without naming its class. The any-class term
// must be the unescaped presence filter: Equal would escape it to
// (objectClass=\2a), a literal match on an asterisk, and every membership edit
// and password set — which all resolve a DN first — would report not-found.
func TestAnyClassLookupResolvesAcrossClasses(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	g, err := d.Group.Create(ctx, adcore.GroupSpec{
		Name: "Holder", SamAccountName: "Holder", Container: d.DNC,
		Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
	})
	if err != nil {
		t.Fatalf("Create group: %v", err)
	}
	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("member"), SamAccountName: "member", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create user: %v", err)
	}

	// AddMembers resolves the member's DN without knowing its class.
	if err := d.Group.AddMembers(ctx, adcore.ByGUID(g.GUID),
		[]adcore.Identity{adcore.ByGUID(u.GUID)}); err != nil {
		t.Fatalf("AddMembers had to resolve a DN by GUID alone: %v", err)
	}
}
