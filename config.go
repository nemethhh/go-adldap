package adldap

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/nemethhh/go-adcore"
)

// TLSMode selects how the connection is protected. There is no "none".
type TLSMode string

const (
	TLSLDAPS    TLSMode = "ldaps"
	TLSStartTLS TLSMode = "starttls"
)

// DefaultPort is the port a mode uses when Config.Port is zero.
func DefaultPort(m TLSMode) int {
	if m == TLSStartTLS {
		return 389
	}
	return 636
}

// SimpleAuth is a username and password bind. It requires TLS, which this
// package always has.
type SimpleAuth struct {
	Username string // a UPN, a DN, or DOMAIN\user
	Password adcore.Secret
}

// KerberosAuth binds with a Kerberos ticket. The zero value uses the ambient
// credential cache, which is the intended path: an operator runs kinit in
// their own shell and no password reaches Terraform configuration.
//
// Resolution order is CCachePath, then KRB5CCNAME, then Keytab.
type KerberosAuth struct {
	// CCachePath names a credential cache file explicitly.
	CCachePath string
	// Keytab and Username authenticate unattended, for CI with no kinit.
	Keytab   string
	Username string
	Realm    string
	// Krb5ConfPath overrides /etc/krb5.conf.
	Krb5ConfPath string
	// SPN overrides the service principal, which defaults to ldap/<server>.
	SPN string
}

// NTLMAuth binds with NTLM, for callers that cannot obtain a TGT.
type NTLMAuth struct {
	Domain   string
	Username string
	Password adcore.Secret
}

// Config configures a Client. Server, TLS and exactly one auth block are
// required.
type Config struct {
	// Server is the domain controller this client pins for its lifetime.
	Server string
	Port   int

	TLS TLSMode
	// CACertificateFile verifies the DC's certificate. Empty uses the system
	// pool.
	CACertificateFile string
	// InsecureSkipVerify disables certificate verification. It is never a
	// default and exists only for labs with self-signed DC certificates.
	InsecureSkipVerify bool
	// TLSConfig, when set, wins over the three fields above. Test hook.
	TLSConfig *tls.Config

	// Exactly one of these.
	Simple   *SimpleAuth
	Kerberos *KerberosAuth
	NTLM     *NTLMAuth

	// MaxConcurrency bounds pooled connections. Zero means 4.
	MaxConcurrency int
	// Timeout is the per-operation deadline. Zero means 60s.
	Timeout time.Duration

	Retry       adcore.RetryConfig
	Replication ReplicationConfig

	Log Logger
}

// ReplicationConfig governs the wait that follows a write.
type ReplicationConfig struct {
	Wait         bool
	Targets      []string // DC host names, or the single element "all"
	ForceSync    bool
	Timeout      time.Duration
	PollInterval time.Duration
}

// Logger is the output port. The package masks credential-bearing values
// before anything reaches it: redaction cannot be the caller's job, because
// the caller never sees the payload.
type Logger interface {
	Debug(ctx context.Context, msg string, kv ...any)
}

func constraint(msg string) error {
	return &adcore.Error{Kind: adcore.KindConstraint, Op: "New", Err: errors.New("adldap: " + msg)}
}

// Validate checks the configuration before any dial.
func (c Config) Validate() error {
	if c.Server == "" {
		return constraint("Config.Server is required; there is no discovery, because a pinned DC is an invariant")
	}
	switch c.TLS {
	case TLSLDAPS, TLSStartTLS:
	case "":
		return constraint(`Config.TLS is required: "ldaps" or "starttls". Plain LDAP is not offered`)
	default:
		return constraint(`Config.TLS must be "ldaps" or "starttls"`)
	}

	n := 0
	for _, set := range []bool{c.Simple != nil, c.Kerberos != nil, c.NTLM != nil} {
		if set {
			n++
		}
	}
	switch n {
	case 1:
	case 0:
		return constraint("exactly one of Simple, Kerberos or NTLM is required; there is no default, because guessing would authenticate as the wrong identity")
	default:
		return constraint("exactly one of Simple, Kerberos or NTLM may be set")
	}

	if c.Simple != nil && c.Simple.Username == "" {
		return constraint("Simple.Username is required")
	}
	if c.NTLM != nil && c.NTLM.Username == "" {
		return constraint("NTLM.Username is required")
	}
	return nil
}
