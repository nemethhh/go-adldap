package conn

import (
	"strings"
	"testing"
)

// A password needs a principal to go with it. Without one the AS-REQ has no
// client name and the KDC answers with something about an unknown principal,
// a long way from the actual mistake.
func TestPasswordSourceRequiresAUsername(t *testing.T) {
	_, err := newTicketSource(ticketSourceOptions{
		Password: "hunter2",
		Realm:    "CORP.LOCAL",
		KDC:      "dc01.corp.local",
		Getenv:   env(nil),
	})
	if err == nil {
		t.Fatal("a password with no username was accepted")
	}
	if !strings.Contains(err.Error(), "Username") {
		t.Errorf("error should name the missing username: %v", err)
	}
}

// With no realm configured, the pinned server supplies one. This is what lets
// kerberos { username, password } work with nothing else set.
func TestPasswordSourceDerivesTheRealmFromTheServer(t *testing.T) {
	src, err := newTicketSource(ticketSourceOptions{
		Password:     "hunter2",
		Username:     "svc_tf",
		KDC:          "dc01.corp.local",
		Krb5ConfPath: "", // synthesized: this host may have no krb5.conf
		Getenv:       env(nil),
	})
	if err != nil {
		t.Fatalf("newTicketSource: %v", err)
	}
	defer src.Destroy()

	if got := src.Realm(); got != "CORP.LOCAL" {
		t.Errorf("Realm() = %q, want CORP.LOCAL derived from dc01.corp.local", got)
	}
}

// No credential of any kind still falls back to the ambient cache, which is
// the intended path and must not regress.
func TestNoCredentialFallsBackToKRB5CCNAME(t *testing.T) {
	_, err := newTicketSource(ticketSourceOptions{
		KDC:    "dc01.corp.local",
		Realm:  "CORP.LOCAL",
		Getenv: env(nil), // KRB5CCNAME unset
	})
	if err == nil {
		t.Fatal("no credential and no KRB5CCNAME was accepted")
	}
	if !strings.Contains(err.Error(), "KRB5CCNAME") {
		t.Errorf("error should name KRB5CCNAME, the fallback that was missing: %v", err)
	}
}

// A keytab that is not there must say so plainly.
func TestKeytabSourceReportsAMissingFile(t *testing.T) {
	_, err := newTicketSource(ticketSourceOptions{
		Keytab:   "/nonexistent/svc.keytab",
		Username: "svc_tf",
		Realm:    "CORP.LOCAL",
		KDC:      "dc01.corp.local",
		Getenv:   env(nil),
	})
	if err == nil {
		t.Fatal("a missing keytab was accepted")
	}
	if !strings.Contains(err.Error(), "/nonexistent/svc.keytab") {
		t.Errorf("error should name the keytab: %v", err)
	}
}
