package adtest_test

import (
	"context"
	"testing"

	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// The harness answers a rootDSE base search, which is what New needs to pin a
// DC. If this passes, the whole dial/TLS/bind/search path works end to end
// against a real LDAP server.
func TestHarnessServesRootDSE(t *testing.T) {
	srv := adtest.Start(t)

	client, err := adldap.New(context.Background(), srv.Config())
	if err != nil {
		t.Fatalf("New against the harness: %v", err)
	}
	defer client.Close()

	if got := client.DefaultNamingContext(); got != "DC=corp,DC=local" {
		t.Errorf("DefaultNamingContext = %q, want %q", got, "DC=corp,DC=local")
	}
	if got := client.Server(); got == "" {
		t.Error("Server must report the pinned DC")
	}
}

// A wrong password must fail the bind, or every later test would pass against
// a server that authenticates nobody.
func TestHarnessRejectsABadPassword(t *testing.T) {
	srv := adtest.Start(t)
	cfg := srv.Config()
	cfg.Simple.Password = adtest.WrongPassword()

	if _, err := adldap.New(context.Background(), cfg); err == nil {
		t.Fatal("New with a wrong password must fail")
	}
}

// The certificate is verified, not skipped: Config hands back a pool holding
// the server's own CA. A harness that only worked with InsecureSkipVerify
// would never exercise the verification path the real client uses.
func TestHarnessCertificateVerifies(t *testing.T) {
	srv := adtest.Start(t)
	cfg := srv.Config()
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify {
		t.Fatal("the harness must present a verifiable certificate, not skip verification")
	}
	client, err := adldap.New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New with certificate verification on: %v", err)
	}
	client.Close()
}
