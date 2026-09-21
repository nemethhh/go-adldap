package conn

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveCCachePathStripsFilePrefix(t *testing.T) {
	got, err := ResolveCCachePath("", env(map[string]string{"KRB5CCNAME": "FILE:/tmp/krb5cc_1000"}))
	if err != nil {
		t.Fatalf("ResolveCCachePath: %v", err)
	}
	if got != "/tmp/krb5cc_1000" {
		t.Errorf("got %q, want the path with the FILE: prefix stripped", got)
	}
}

func TestResolveCCachePathAcceptsBarePath(t *testing.T) {
	got, err := ResolveCCachePath("", env(map[string]string{"KRB5CCNAME": "/tmp/krb5cc_1000"}))
	if err != nil {
		t.Fatalf("ResolveCCachePath: %v", err)
	}
	if got != "/tmp/krb5cc_1000" {
		t.Errorf("got %q", got)
	}
}

func TestExplicitPathWinsOverEnvironment(t *testing.T) {
	got, err := ResolveCCachePath("/explicit/cc", env(map[string]string{"KRB5CCNAME": "FILE:/tmp/other"}))
	if err != nil {
		t.Fatalf("ResolveCCachePath: %v", err)
	}
	if got != "/explicit/cc" {
		t.Errorf("got %q, want configuration to win over the environment", got)
	}
}

// gokrb5 reads FILE ccaches with os.ReadFile and nothing else. RHEL and Fedora
// with sssd default to KEYRING, Ubuntu with sssd-kcm to KCM, and neither is
// readable. The error must name the fix, because "no ticket found" sends the
// user hunting for a kinit they already ran.
func TestUnreadableCCacheTypesNameTheFix(t *testing.T) {
	for _, val := range []string{"KEYRING:persistent:1000", "KCM:1000", "DIR:/run/user/1000/krb5cc"} {
		_, err := ResolveCCachePath("", env(map[string]string{"KRB5CCNAME": val}))
		if err == nil {
			t.Fatalf("KRB5CCNAME=%q must be an error", val)
		}
		if !strings.Contains(err.Error(), "KRB5CCNAME=FILE:") {
			t.Errorf("KRB5CCNAME=%q error does not name the fix: %v", val, err)
		}
	}
}

// A Windows path is not a ccache type. Splitting on the first colon would read
// "C" as a scheme and tell the operator to fix a cache type they never named.
func TestWindowsPathIsNotMistakenForAScheme(t *testing.T) {
	got, err := ResolveCCachePath("", env(map[string]string{"KRB5CCNAME": `C:\Users\svc\krb5cc`}))
	if err != nil {
		t.Fatalf("ResolveCCachePath: %v", err)
	}
	if got != `C:\Users\svc\krb5cc` {
		t.Errorf("got %q, want the path unchanged", got)
	}
}

func TestNoCCacheAtAll(t *testing.T) {
	if _, err := ResolveCCachePath("", env(nil)); err == nil {
		t.Fatal("no explicit path and no KRB5CCNAME must be an error")
	}
}
