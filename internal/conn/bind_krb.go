package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
)

// KerberosBinder binds with a Kerberos ticket.
//
// The preferred path remains the ambient credential cache: an operator runs
// kinit in their own shell and no password reaches Terraform configuration.
// Keytab and Password are the unattended alternatives, for CI and for any
// runner where kinit was never installed.
//
// Every bind carries a tls-server-end-point channel-binding token, which is
// what a domain with LdapEnforceChannelBinding = 2 requires. That setting is
// in the CIS Benchmark and the DISA STIG, so it is the configuration of the
// domains most likely to be automated. Sending it unconditionally is what a
// Windows client does: a controller at 0 ignores the token, at 1 validates it
// when present, at 2 requires it.
//
// This is the Linux and macOS path. Windows keeps credentials in the LSA with
// no readable ccache, so a Windows operator uses simple or NTLM until an SSPI
// client lands behind this seam.
type KerberosBinder struct {
	CCachePath   string
	Keytab       string
	Password     string
	Username     string
	Realm        string
	Krb5ConfPath string
	SPN          string // defaults to ldap/<host>

	Host   string
	Getenv func(string) string
}

var _ Binder = KerberosBinder{}

func (b KerberosBinder) Describe() string {
	switch {
	case b.Keytab != "":
		return fmt.Sprintf("GSSAPI bind as %s@%s from a keytab", b.Username, b.Realm)
	case b.Password != "":
		return fmt.Sprintf("GSSAPI bind as %s@%s from a supplied password", b.Username, b.Realm)
	default:
		return "GSSAPI bind from the ambient credential cache"
	}
}

func (b KerberosBinder) spn() string {
	if b.SPN != "" {
		return b.SPN
	}
	return "ldap/" + b.Host
}

// tokenForCertificate is the channel binding for one connection. Split out so
// the derivation can be tested without a domain controller.
func (b KerberosBinder) tokenForCertificate(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	return channelBindingToken(cert)
}

// peerCertificate reads the leaf certificate the connection actually
// negotiated. Split out from Bind so a literal tls.ConnectionState can pin
// that extraction directly — the risk is a future refactor that sources the
// certificate from configuration instead of the live handshake, which no
// test on tokenForCertificate alone would catch.
func peerCertificate(state tls.ConnectionState, ok bool) *x509.Certificate {
	if !ok || len(state.PeerCertificates) == 0 {
		return nil
	}
	return state.PeerCertificates[0]
}

func (b KerberosBinder) Bind(ctx context.Context, c Conn) error {
	g, ok := c.(*goldapConn)
	if !ok {
		return errWrongConn("KerberosBinder")
	}

	getenv := b.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	// The certificate comes from the connection that is about to be bound,
	// never from configuration. Binding to anything else is the one mistake
	// channel binding exists to detect.
	state, tlsOK := g.l.TLSConnectionState()
	cert := peerCertificate(state, tlsOK)
	if cert == nil {
		// TLS is already mandatory throughout this package (dial.go never
		// connects without it), so this is unreachable today. It stays a hard
		// error rather than a silent fall-through to no channel binding,
		// because that fall-through is exactly the downgrade this feature
		// exists to prevent — binding without a token while believing
		// otherwise is worse than refusing to bind at all.
		return errors.New("adldap: no TLS state on this connection; TLS is mandatory in this " +
			"package, and binding without a channel-binding token would be a silent downgrade")
	}

	src, err := newTicketSource(ticketSourceOptions{
		CCachePath:   b.CCachePath,
		Keytab:       b.Keytab,
		Password:     b.Password,
		Username:     b.Username,
		Realm:        b.Realm,
		Krb5ConfPath: b.Krb5ConfPath,
		KDC:          b.Host,
		Getenv:       getenv,
	})
	if err != nil {
		return annotateTicketError(err)
	}
	// A fresh source is built on every Bind, so destroying this one leaves the
	// Binder reusable for the pool's reconnect — which the Binder contract
	// requires.
	client := newGSSClient(src, b.tokenForCertificate(cert))
	defer func() { _ = client.Close() }()

	return annotateTicketError(toRawError(g.l.GSSAPIBindRequestWithAPOptions(client, &ldap.GSSAPIBindRequest{
		ServicePrincipalName: b.spn(),
	}, apOptions())))
}

// apOptions are the AP-REQ options the bind sends.
//
// mutual-required is not optional against Active Directory, and leaving it out
// is why the plain GSSAPIBind helper cannot bind to a domain controller at all.
// That helper passes no AP options while the GSSAPI checksum it builds requests
// ContextFlagMutual, so the AP-REQ asks for mutual authentication in one field
// and not in the other. AD refuses the inconsistency with
//
//	AcceptSecurityContext error, data 57
//
// which is ERROR_INVALID_PARAMETER — a message that names neither Kerberos nor
// the field, and reads like a credential problem when the ticket is perfect.
// Setting the option makes the two agree and the bind succeeds.
func apOptions() []int { return []int{flags.APOptionMutualRequired} }

// annotateTicketError turns terse Kerberos failures into something an operator
// can act on.
func annotateTicketError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "TGT not found in CCache"):
		return fmt.Errorf("%w: the credential cache holds no ticket-granting ticket; run kinit again", err)
	case strings.Contains(msg, "KDC_ERR_PREAUTH_FAILED"):
		return fmt.Errorf("%w: the KDC rejected the credential; the password is wrong, or the "+
			"account is disabled or locked out", err)
	case strings.Contains(msg, "KDC_ERR_C_PRINCIPAL_UNKNOWN"):
		return fmt.Errorf("%w: the KDC does not know that principal; check both the username and "+
			"the realm — when Kerberos.Realm is unset it is derived from Config.Server's domain "+
			"suffix, uppercased", err)
	case strings.Contains(msg, "expired"), strings.Contains(msg, "Ticket expired"):
		return fmt.Errorf("%w: the Kerberos ticket has expired; run kinit again "+
			"(AD's default ticket lifetime is 10 hours and it is not renewed automatically)", err)
	}
	return err
}

// SPNForTest exposes the resolved service principal, which is not otherwise
// observable without a KDC.
func (b KerberosBinder) SPNForTest() string { return b.spn() }
