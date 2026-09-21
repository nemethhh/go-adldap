package conn

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildTLSConfigUsesServerName(t *testing.T) {
	cfg, err := BuildTLSConfig("dc01.corp.local", "", false)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ServerName != "dc01.corp.local" {
		t.Errorf("ServerName = %q, want the host", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Error("verification must be on unless explicitly disabled")
	}
	if cfg.MinVersion < tls.VersionTLS12 {
		t.Error("MinVersion must be at least TLS 1.2")
	}
}

func TestBuildTLSConfigRejectsUnreadableCA(t *testing.T) {
	if _, err := BuildTLSConfig("dc01.corp.local", filepath.Join(t.TempDir(), "missing.pem"), false); err == nil {
		t.Fatal("an unreadable CA file must be an error, not a silent fallback to the system pool")
	}
}

func TestBuildTLSConfigRejectsNonPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildTLSConfig("dc01.corp.local", path, false); err == nil {
		t.Fatal("a CA file containing no certificate must be an error")
	}
}

// Naming a CA file must actually put that CA in the trust pool. Asserting
// only that RootCAs is non-nil would pass on an empty pool, which verifies
// nothing and fails at dial time instead of here.
func TestBuildTLSConfigTrustsTheNamedCA(t *testing.T) {
	const host = "dc01.corp.local"
	caPEM, leaf := newTestCA(t, host)

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := BuildTLSConfig(host, path, false)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs must be set when a CA file is named")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: host}); err != nil {
		t.Errorf("a certificate signed by the named CA did not verify against the pool: %v", err)
	}
}
