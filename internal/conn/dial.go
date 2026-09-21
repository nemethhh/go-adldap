package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// BuildTLSConfig assembles the TLS configuration for a DC connection.
//
// An unreadable or certificate-free CA file is an error rather than a silent
// fall back to the system pool: falling back would verify against a trust
// store the operator did not choose, which is the opposite of what naming a
// CA file asks for.
func BuildTLSConfig(host, caFile string, skipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify, //nolint:gosec // never a default; see Config.InsecureSkipVerify
	}
	if caFile == "" {
		return cfg, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("adldap: cannot read CA certificate %q: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("adldap: %q contains no PEM certificate", caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

type DialOptions struct {
	Host      string
	Port      int
	StartTLS  bool
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// Dial opens one TLS-protected LDAP connection. It does not bind.
func Dial(ctx context.Context, o DialOptions) (Conn, error) {
	addr := net.JoinHostPort(o.Host, strconv.Itoa(o.Port))
	d := &net.Dialer{Timeout: o.Timeout}

	var (
		l   *ldap.Conn
		err error
	)
	if o.StartTLS {
		// The cleartext phase carries only the StartTLS extended request; the
		// bind happens after the upgrade, never before it.
		l, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(d))
		if err != nil {
			return nil, err
		}
		if err := l.StartTLS(o.TLSConfig); err != nil {
			l.Close()
			return nil, err
		}
	} else {
		l, err = ldap.DialURL("ldaps://"+addr,
			ldap.DialWithDialer(d), ldap.DialWithTLSConfig(o.TLSConfig))
		if err != nil {
			return nil, err
		}
	}
	if o.Timeout > 0 {
		l.SetTimeout(o.Timeout)
	}
	return &goldapConn{l: l}, nil
}
