package adldap_test

import (
	"context"
	"testing"

	adldap "github.com/nemethhh/go-adldap"
)

func TestNewRejectsAnInvalidConfig(t *testing.T) {
	if _, err := adldap.New(context.Background(), adldap.Config{}); err == nil {
		t.Fatal("New must validate before dialling")
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

// binderForHost runs again for the replication probe's second controller.
// Deriving the realm from that host rather than from Config.Server would
// still pass every other test here, because both existing cross-host cases
// share the corp.local suffix; only a genuinely different suffix can tell the
// two derivations apart.
func TestKerberosRealmFollowsConfigServerNotTheDialledHost(t *testing.T) {
	cfg := adldap.Config{
		Server:   "dc01.corp.local",
		TLS:      adldap.TLSLDAPS,
		Kerberos: &adldap.KerberosAuth{},
	}
	if got := adldap.BinderRealmForHost(cfg, "dc99.other.example"); got != "CORP.LOCAL" {
		t.Errorf("realm = %q, want CORP.LOCAL (derived from Config.Server, not the dialled host)", got)
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
