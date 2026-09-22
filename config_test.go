package adldap_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
)

// Exactly one auth block, for the same reason the provider requires exactly
// one connection block: guessing would authenticate as the wrong identity.
func TestConfigRequiresExactlyOneAuth(t *testing.T) {
	base := adldap.Config{Server: "dc01.corp.local", TLS: adldap.TLSLDAPS}

	t.Run("none", func(t *testing.T) {
		if err := base.Validate(); err == nil {
			t.Fatal("zero auth blocks must be an error")
		}
	})

	t.Run("two", func(t *testing.T) {
		c := base
		c.Simple = &adldap.SimpleAuth{Username: "u", Password: adcore.NewSecret("p")}
		c.Kerberos = &adldap.KerberosAuth{}
		if err := c.Validate(); err == nil {
			t.Fatal("two auth blocks must be an error")
		}
	})

	t.Run("one", func(t *testing.T) {
		c := base
		c.Kerberos = &adldap.KerberosAuth{}
		if err := c.Validate(); err != nil {
			t.Fatalf("one auth block must validate: %v", err)
		}
	})
}

func TestConfigRequiresServerAndTLS(t *testing.T) {
	c := adldap.Config{Kerberos: &adldap.KerberosAuth{}}
	err := c.Validate()
	if err == nil {
		t.Fatal("a Config with no Server must be an error")
	}
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindConstraint {
		t.Fatalf("want a KindConstraint adcore.Error, got %#v", err)
	}
}

// Plain LDAP is not a mode. A config that names one is refused rather than
// quietly downgraded, because a simple bind over 389 sends the password in
// clear text.
func TestConfigRejectsPlainLDAP(t *testing.T) {
	c := adldap.Config{Server: "dc01.corp.local", TLS: adldap.TLSMode("none"), Kerberos: &adldap.KerberosAuth{}}
	if err := c.Validate(); err == nil {
		t.Fatal(`TLS "none" must be an error`)
	}
}

func TestDefaultPort(t *testing.T) {
	if got := adldap.DefaultPort(adldap.TLSLDAPS); got != 636 {
		t.Errorf("ldaps port = %d, want 636", got)
	}
	if got := adldap.DefaultPort(adldap.TLSStartTLS); got != 389 {
		t.Errorf("starttls port = %d, want 389", got)
	}
}

// Two credential sources is a configuration mistake, not a precedence
// question. Picking one silently would authenticate as an identity the
// operator did not choose.
func TestTwoKerberosCredentialSourcesIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth adldap.KerberosAuth
	}{
		{"keytab and password", adldap.KerberosAuth{Keytab: "/k.keytab", Password: adcore.NewSecret("p"), Username: "u"}},
		{"ccache and password", adldap.KerberosAuth{CCachePath: "/tmp/cc", Password: adcore.NewSecret("p"), Username: "u"}},
		{"ccache and keytab", adldap.KerberosAuth{CCachePath: "/tmp/cc", Keytab: "/k.keytab", Username: "u"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := adldap.Config{Server: "dc01.corp.local", TLS: adldap.TLSLDAPS, Kerberos: &tc.auth}
			if err := c.Validate(); err == nil {
				t.Fatal("two credential sources were accepted")
			}
		})
	}
}

// One source, or none, is fine. None means the ambient cache, which is the
// intended path and must keep validating.
func TestOneOrNoKerberosCredentialSourceIsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth adldap.KerberosAuth
	}{
		{"none, the ambient cache", adldap.KerberosAuth{}},
		{"password", adldap.KerberosAuth{Password: adcore.NewSecret("p"), Username: "u"}},
		{"keytab", adldap.KerberosAuth{Keytab: "/k.keytab", Username: "u"}},
		{"ccache", adldap.KerberosAuth{CCachePath: "/tmp/cc"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := adldap.Config{Server: "dc01.corp.local", TLS: adldap.TLSLDAPS, Kerberos: &tc.auth}
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// A password with no principal cannot produce an AS-REQ. Catching it here is
// better than the KDC's report of an unknown principal.
func TestKerberosPasswordRequiresAUsername(t *testing.T) {
	c := adldap.Config{Server: "dc01.corp.local", TLS: adldap.TLSLDAPS,
		Kerberos: &adldap.KerberosAuth{Password: adcore.NewSecret("hunter2")}}
	err := c.Validate()
	if err == nil {
		t.Fatal("a password with no username was accepted")
	}
	if !strings.Contains(err.Error(), "Username") {
		t.Errorf("error should name the missing username: %v", err)
	}
}
