package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestNewRejectsAnInvalidConfig(t *testing.T) {
	if _, err := adldap.New(context.Background(), adldap.Config{}); err == nil {
		t.Fatal("New must validate before dialling")
	}
}

// The classes this backend has not implemented must answer with a Kind, not a
// nil dereference. A nil interface field panics inside the consumer, which on
// the lab aborted an entire acceptance run and named neither the class nor the
// reason.
func TestUnimplementedClassesReportUnsupported(t *testing.T) {
	d := adtest.StartMemory(t).Directory(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"ACL.Get":        func() error { _, err := d.ACL.Get(ctx, adcore.ByGUID("x")); return err },
		"ACL.Grant":      func() error { return d.ACL.Grant(ctx, adcore.ByGUID("x"), nil) },
		"Schema.Resolve": func() error { _, err := d.Schema.Resolve(ctx, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var e *adcore.Error
			if !errors.As(err, &e) || e.Kind != adcore.KindUnsupported {
				t.Fatalf("want KindUnsupported, got %#v", err)
			}
		})
	}
}

// The Kerberos SPN must follow the host actually dialled. The replication wait
// opens a connection to a second controller, and reusing the pinned DC's binder
// there presents a ticket for the wrong service: AD refuses it, the probe never
// sees the object, and the wait spins to its deadline — which reads as slow
// replication rather than as a bad SPN.
func TestKerberosSPNFollowsTheHostDialled(t *testing.T) {
	cfg := adldap.Config{
		Server:   "dc01.corp.local",
		TLS:      adldap.TLSLDAPS,
		Kerberos: &adldap.KerberosAuth{},
	}
	pinned := adldap.BinderDescriptionForHost(cfg, "dc01.corp.local")
	other := adldap.BinderDescriptionForHost(cfg, "dc02.corp.local")
	if pinned == other {
		t.Fatalf("both hosts produced the same binder description %q; the SPN did not follow the host", pinned)
	}
}

// An explicit SPN still wins over the per-host default.
func TestExplicitKerberosSPNWinsOverTheHost(t *testing.T) {
	cfg := adldap.Config{
		Server:   "dc01.corp.local",
		TLS:      adldap.TLSLDAPS,
		Kerberos: &adldap.KerberosAuth{SPN: "ldap/pinned.corp.local"},
	}
	if a, b := adldap.BinderDescriptionForHost(cfg, "dc01.corp.local"),
		adldap.BinderDescriptionForHost(cfg, "dc02.corp.local"); a != b {
		t.Errorf("an explicit SPN should not vary by host: %q vs %q", a, b)
	}
}
