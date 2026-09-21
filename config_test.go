package adldap_test

import (
	"errors"
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
