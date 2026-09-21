package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestGMSACreateReadsBack(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
		Name:                          "svc-web",
		SamAccountName:                "svc-web",
		Container:                     d.DNC,
		DNSHostName:                   adcore.String("svc-web.corp.local"),
		Description:                   adcore.String("the web service account"),
		ManagedPasswordIntervalInDays: adcore.Int(30),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.DN != "CN=svc-web,"+d.DNC {
		t.Errorf("DN = %q", created.DN)
	}
	if created.SamAccountName != "svc-web" {
		t.Errorf("SamAccountName = %q, want the $ stripped", created.SamAccountName)
	}
	if created.DNSHostName != "svc-web.corp.local" {
		t.Errorf("DNSHostName = %q", created.DNSHostName)
	}
	if created.ManagedPasswordIntervalInDays != 30 {
		t.Errorf("ManagedPasswordIntervalInDays = %d, want 30", created.ManagedPasswordIntervalInDays)
	}
	if !created.Enabled {
		t.Error("a gMSA created with no Enabled in the spec should be enabled")
	}
}

// AD refuses a gMSA with no msDS-GroupMSAMembership. Creating one without the
// attribute fails on a real domain and passes against a permissive fake, which
// is exactly the class of bug the lab catches and CI does not — so assert on
// the wire value.
func TestGMSACreateAlwaysWritesMembership(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	if _, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
		Name: "svc-none", SamAccountName: "svc-none", Container: d.DNC,
		DNSHostName: adcore.String("svc-none.corp.local"),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	e := m.Entries()["CN=svc-none,"+d.DNC]
	if len(e["msDS-GroupMSAMembership"]) == 0 {
		t.Fatal("msDS-GroupMSAMembership was not written; AD refuses a gMSA without it")
	}
	if got := string(e["sAMAccountName"][0]); got != "svc-none$" {
		t.Errorf("sAMAccountName = %q, want %q", got, "svc-none$")
	}
}

func TestGMSAPrincipalsRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	host, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "APP01", SamAccountName: "APP01", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create APP01: %v", err)
	}

	created, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
		Name: "svc-app", SamAccountName: "svc-app", Container: d.DNC,
		DNSHostName:       adcore.String("svc-app.corp.local"),
		PrincipalsAllowed: []adcore.Identity{adcore.ByGUID(host.GUID)},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(created.PrincipalsAllowed) != 1 || created.PrincipalsAllowed[0] != host.GUID {
		t.Fatalf("PrincipalsAllowed = %v, want [%s]", created.PrincipalsAllowed, host.GUID)
	}

	cleared, err := d.ServiceAccount.Update(ctx, adcore.ByGUID(created.GUID), adcore.GMSASpec{
		Name: "svc-app", SamAccountName: "svc-app", Container: d.DNC,
		DNSHostName:       adcore.String("svc-app.corp.local"),
		PrincipalsAllowed: []adcore.Identity{},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(cleared.PrincipalsAllowed) != 0 {
		t.Errorf("PrincipalsAllowed = %v, want empty", cleared.PrincipalsAllowed)
	}
}

// The interval is create-only. An Update naming a different one must not send
// a modify: AD refuses it, and the refusal would surface as a failed apply on
// a field the user did not knowingly change.
func TestGMSAUpdateIgnoresTheManagedPasswordInterval(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	created, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
		Name: "svc-int", SamAccountName: "svc-int", Container: d.DNC,
		DNSHostName:                   adcore.String("svc-int.corp.local"),
		ManagedPasswordIntervalInDays: adcore.Int(30),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := d.ServiceAccount.Update(ctx, adcore.ByGUID(created.GUID), adcore.GMSASpec{
		Name: "svc-int", SamAccountName: "svc-int", Container: d.DNC,
		DNSHostName:                   adcore.String("svc-int.corp.local"),
		ManagedPasswordIntervalInDays: adcore.Int(90),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.ManagedPasswordIntervalInDays != 30 {
		t.Errorf("the interval changed to %d; it is create-only and must be ignored on update",
			updated.ManagedPasswordIntervalInDays)
	}
}

func TestGMSASearchAndDelete(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	for _, n := range []string{"svc-a", "svc-b"} {
		if _, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{
			Name: n, SamAccountName: n, Container: d.DNC,
			DNSHostName: adcore.String(n + ".corp.local"),
		}); err != nil {
			t.Fatalf("Create %s: %v", n, err)
		}
	}

	found, err := d.ServiceAccount.Search(ctx, adcore.Query{SearchBase: d.DNC})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("Search found %d, want 2", len(found))
	}

	if err := d.ServiceAccount.Delete(ctx, adcore.ByGUID(found[0].GUID)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.ServiceAccount.Get(ctx, adcore.ByGUID(found[0].GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
}
