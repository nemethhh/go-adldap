package conn

import (
	"os"
	"strings"
	"testing"
)

func statFound(string) (os.FileInfo, error)    { return nil, nil }
func statMissing(string) (os.FileInfo, error)  { return nil, os.ErrNotExist }

// A realm has to come from somewhere when nothing is configured. The pinned
// server's domain suffix is the only thing available, and uppercasing it is
// the Active Directory convention.
func TestRealmFromServer(t *testing.T) {
	for _, tc := range []struct{ server, want string }{
		{"dc01.corp.local", "CORP.LOCAL"},
		{"DC01.Corp.Local", "CORP.LOCAL"},
		{"dc01", ""},
		{"", ""},
	} {
		if got := RealmFromServer(tc.server); got != tc.want {
			t.Errorf("RealmFromServer(%q) = %q, want %q", tc.server, got, tc.want)
		}
	}
}

// The synthesized file must name the realm, point it at the pinned DC, and
// turn off the DNS lookups — a host with no krb5.conf generally has no SRV
// records configured for us either, and a lookup that silently fails costs a
// timeout instead of producing an error.
func TestSynthesizedConfigNamesTheRealmAndKDC(t *testing.T) {
	got, err := synthesizeKrb5Conf("CORP.LOCAL", "dc01.corp.local")
	if err != nil {
		t.Fatalf("synthesizeKrb5Conf: %v", err)
	}
	for _, want := range []string{
		"default_realm = CORP.LOCAL",
		"kdc = dc01.corp.local",
		"dns_lookup_kdc = false",
		"CORP.LOCAL = {",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("synthesized config missing %q:\n%s", want, got)
		}
	}
}

// Whatever we generate has to parse. A config the library rejects would fail
// at bind time with an error about syntax rather than about credentials.
func TestSynthesizedConfigParses(t *testing.T) {
	cfg, err := loadKrb5Conf("", "CORP.LOCAL", "dc01.corp.local", statMissing)
	if err != nil {
		t.Fatalf("loadKrb5Conf: %v", err)
	}
	if cfg.LibDefaults.DefaultRealm != "CORP.LOCAL" {
		t.Errorf("DefaultRealm = %q, want CORP.LOCAL", cfg.LibDefaults.DefaultRealm)
	}
	if len(cfg.Realms) != 1 || len(cfg.Realms[0].KDC) == 0 {
		t.Fatalf("realms = %+v, want one realm with a KDC", cfg.Realms)
	}
	if !strings.Contains(cfg.Realms[0].KDC[0], "dc01.corp.local") {
		t.Errorf("KDC = %q, want the pinned server", cfg.Realms[0].KDC[0])
	}
}

// A named file that does not exist is an error, not a fallback. The caller
// asked for that file; silently using a different configuration would
// authenticate against a KDC they did not choose.
func TestNamedConfigMustExist(t *testing.T) {
	_, err := loadKrb5Conf("/nonexistent/krb5.conf", "CORP.LOCAL", "dc01.corp.local", statMissing)
	if err == nil {
		t.Fatal("a missing explicit krb5.conf was accepted")
	}
	if !strings.Contains(err.Error(), "/nonexistent/krb5.conf") {
		t.Errorf("error does not name the file the caller asked for: %v", err)
	}
}

// Synthesis needs a realm. Guessing one would send the AS-REQ to the wrong
// place and report a principal that does not exist.
func TestSynthesisRequiresARealm(t *testing.T) {
	_, err := loadKrb5Conf("", "", "dc01.corp.local", statMissing)
	if err == nil {
		t.Fatal("synthesis without a realm was accepted")
	}
	if !strings.Contains(err.Error(), "realm") {
		t.Errorf("error should name the missing realm: %v", err)
	}
}

// An existing /etc/krb5.conf wins over synthesis: it may carry enctype
// restrictions or several KDCs the operator configured deliberately.
func TestSystemConfigWinsOverSynthesis(t *testing.T) {
	var asked string
	stat := func(p string) (os.FileInfo, error) { asked = p; return statFound(p) }

	// It will fail to read a file this test has not created; what is asserted
	// is that it tried the system path rather than synthesizing.
	_, _ = loadKrb5Conf("", "CORP.LOCAL", "dc01.corp.local", stat)
	if asked != systemKrb5Conf {
		t.Errorf("stat called with %q, want %q", asked, systemKrb5Conf)
	}
}
