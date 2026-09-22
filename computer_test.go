package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestComputerCreateReadsBack(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name:           "SRV01",
		SamAccountName: "SRV01",
		Container:      d.DNC,
		DNSHostName:    adcore.String("srv01.corp.local"),
		Description:    adcore.String("the first server"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.DN != "CN=SRV01,"+d.DNC {
		t.Errorf("DN = %q, want %q", created.DN, "CN=SRV01,"+d.DNC)
	}
	// The trailing "$" AD requires on the wire must not reach the model, or
	// every plan shows a diff between the configured and the read-back value.
	if created.SamAccountName != "SRV01" {
		t.Errorf("SamAccountName = %q, want %q (the $ must be stripped on read)", created.SamAccountName, "SRV01")
	}
	if created.DNSHostName != "srv01.corp.local" {
		t.Errorf("DNSHostName = %q", created.DNSHostName)
	}
	if !created.Enabled {
		t.Error("a computer created with no Enabled in the spec should be enabled")
	}
	if created.GUID == "" {
		t.Error("Create returned no objectGUID")
	}

	got, err := d.Computer.Get(ctx, adcore.ByGUID(created.GUID))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SamAccountName != created.SamAccountName || got.DN != created.DN {
		t.Errorf("Get returned %+v, want %+v", got, created)
	}
}

// The "$" is what AD stores, so it must actually be sent. Asserting on the
// model alone would pass with an implementation that never wrote it.
func TestComputerCreateSendsTheDollarSuffix(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	if _, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SRV01", SamAccountName: "SRV01", Container: d.DNC,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	e, ok := m.Entries()["CN=SRV01,"+d.DNC]
	if !ok {
		t.Fatal("the computer was not written")
	}
	if got := string(e["sAMAccountName"][0]); got != "SRV01$" {
		t.Errorf("sAMAccountName on the wire = %q, want %q", got, "SRV01$")
	}
	if got := string(e["userAccountControl"][0]); got != "4096" {
		t.Errorf("userAccountControl = %q, want 4096 (WORKSTATION_TRUST_ACCOUNT)", got)
	}
}

func TestComputerCreateAcceptsAnAlreadySuffixedName(t *testing.T) {
	ctx := context.Background()
	m := adtest.StartMemory(t)
	d := m.Directory(t)

	created, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SRV02", SamAccountName: "SRV02$", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.SamAccountName != "SRV02" {
		t.Errorf("SamAccountName = %q, want %q", created.SamAccountName, "SRV02")
	}
	if got := string(m.Entries()["CN=SRV02,"+d.DNC]["sAMAccountName"][0]); got != "SRV02$" {
		t.Errorf("sAMAccountName on the wire = %q, want exactly one $", got)
	}
}

func TestComputerUpdateSetsAndClears(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	created, err := d.Computer.Create(ctx, adcore.ComputerSpec{
		Name: "SRV03", SamAccountName: "SRV03", Container: d.DNC,
		Description: adcore.String("before"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := d.Computer.Update(ctx, adcore.ByGUID(created.GUID), adcore.ComputerSpec{
		Name: "SRV03", SamAccountName: "SRV03", Container: d.DNC,
		Description:            adcore.String("after"),
		Location:               adcore.String("rack 4"),
		Enabled:                adcore.Bool(false),
		TrustedForDelegation:   adcore.Bool(true),
		ServicePrincipalNames:  &[]string{"HOST/srv03.corp.local"},
		KerberosEncryptionType: &[]string{"AES256"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Description != "after" {
		t.Errorf("Description = %q, want %q", updated.Description, "after")
	}
	if updated.Location != "rack 4" {
		t.Errorf("Location = %q", updated.Location)
	}
	if updated.Enabled {
		t.Error("Enabled = true, want false")
	}
	if !updated.TrustedForDelegation {
		t.Error("TrustedForDelegation = false, want true")
	}
	if len(updated.ServicePrincipalNames) != 1 || updated.ServicePrincipalNames[0] != "HOST/srv03.corp.local" {
		t.Errorf("ServicePrincipalNames = %v", updated.ServicePrincipalNames)
	}
	if len(updated.KerberosEncryptionType) != 1 || updated.KerberosEncryptionType[0] != "AES256" {
		t.Errorf("KerberosEncryptionType = %v", updated.KerberosEncryptionType)
	}

	// A nil pointer means "leave alone", and an empty non-nil slice means
	// "replace with nothing". Conflating them makes an unmanaged attribute
	// impossible to express.
	same, err := d.Computer.Update(ctx, adcore.ByGUID(created.GUID), adcore.ComputerSpec{
		Name: "SRV03", SamAccountName: "SRV03", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if same.Description != "after" {
		t.Errorf("a nil Description cleared the attribute; want it left alone")
	}
	if len(same.ServicePrincipalNames) != 1 {
		t.Errorf("a nil ServicePrincipalNames cleared the SPNs; want them left alone")
	}

	cleared, err := d.Computer.Update(ctx, adcore.ByGUID(created.GUID), adcore.ComputerSpec{
		Name: "SRV03", SamAccountName: "SRV03", Container: d.DNC,
		ServicePrincipalNames: &[]string{},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if len(cleared.ServicePrincipalNames) != 0 {
		t.Errorf("an empty non-nil ServicePrincipalNames left %v", cleared.ServicePrincipalNames)
	}
}

func TestComputerSearchAndDelete(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	for _, n := range []string{"SRV10", "SRV11"} {
		if _, err := d.Computer.Create(ctx, adcore.ComputerSpec{
			Name: n, SamAccountName: n, Container: d.DNC,
		}); err != nil {
			t.Fatalf("Create %s: %v", n, err)
		}
	}

	found, err := d.Computer.Search(ctx, adcore.Query{SearchBase: d.DNC})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("Search found %d computers, want 2", len(found))
	}

	if err := d.Computer.Delete(ctx, adcore.ByGUID(found[0].GUID)); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := d.Computer.Get(ctx, adcore.ByGUID(found[0].GUID)); !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Delete is idempotent: a second one is not an error.
	if err := d.Computer.Delete(ctx, adcore.ByGUID(found[0].GUID)); err != nil && !errors.Is(err, adcore.ErrNotFound) {
		t.Errorf("second Delete = %v, want nil or ErrNotFound", err)
	}
}
