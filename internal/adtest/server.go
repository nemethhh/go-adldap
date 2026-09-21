// Package adtest runs an in-process LDAP server backed by an in-memory
// directory, so this module's wire behaviour — attribute encoding, controls,
// filters, paging, binds — is exercised in CI rather than first on a lab
// domain.
//
// It is deliberately not a faithful Active Directory. Conformance to the
// directory contract is asserted by adcoretest against the shared fake; this
// harness asserts that what goes on the wire is correct LDAP.
package adtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"
	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
)

// The password every seeded bind accepts. A test that wants a failing bind
// uses WrongPassword.
const (
	bindDN       = "CN=tester,DC=corp,DC=local"
	bindPassword = "test"

	// DNC is the naming context the harness serves.
	DNC = "DC=corp,DC=local"
)

// WrongPassword is a password the harness always rejects.
func WrongPassword() adcore.Secret { return adcore.NewSecret("not-the-password") }

// Server is a running in-process LDAP server.
type Server struct {
	t    *testing.T
	s    *gldap.Server
	host string
	port int
	// pool trusts the server's own self-signed certificate, so Config can hand
	// a client a TLS configuration that verifies rather than skips.
	pool *x509.CertPool

	mu      sync.Mutex
	entries map[string]map[string][][]byte
	seq     uint32
}

// nextGUID hands out a distinct objectGUID, the way a DC stamps one on create.
func (s *Server) nextGUID() []byte {
	s.seq++
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], s.seq)
	return b
}

// Start brings up an LDAPS listener on a loopback port with a self-signed
// certificate, seeded with a rootDSE and an empty DC=corp,DC=local.
func Start(t *testing.T) *Server {
	t.Helper()

	cert, pool := selfSignedCert(t, "localhost")

	srv := &Server{
		t:       t,
		host:    "localhost",
		pool:    pool,
		entries: map[string]map[string][][]byte{},
	}
	srv.Seed(DNC, map[string][][]byte{
		"objectClass":       {[]byte("top"), []byte("domainDNS")},
		"distinguishedName": {[]byte(DNC)},
	})

	s, err := gldap.NewServer()
	if err != nil {
		t.Fatalf("gldap.NewServer: %v", err)
	}
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatalf("gldap.NewMux: %v", err)
	}
	for name, register := range map[string]func(gldap.HandlerFunc, ...gldap.Option) error{
		"bind":   mux.Bind,
		"search": mux.Search,
		"add":    mux.Add,
		"modify": mux.Modify,
		"delete": mux.Delete,
	} {
		var fn gldap.HandlerFunc
		switch name {
		case "bind":
			fn = srv.handleBind
		case "search":
			fn = srv.handleSearch
		case "add":
			fn = srv.handleAdd
		case "modify":
			fn = srv.handleModify
		case "delete":
			fn = srv.handleDelete
		}
		if err := register(fn); err != nil {
			t.Fatalf("mux.%s: %v", name, err)
		}
	}
	if err := s.Router(mux); err != nil {
		t.Fatalf("s.Router: %v", err)
	}

	// Take a port from the kernel, then hand it to gldap. gldap.Run takes an
	// address rather than a listener, so there is no way to pass the bound
	// socket straight through.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.port = ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}

	go func() {
		_ = s.Run(net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.port)),
			gldap.WithTLSConfig(&tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}))
	}()
	t.Cleanup(func() { _ = s.Stop() })

	srv.s = s
	waitForPort(t, srv.port)
	return srv
}

// Config returns an adldap.Config pointed at this server, trusting its
// certificate.
func (s *Server) Config() adldap.Config {
	return adldap.Config{
		Server:    s.host,
		Port:      s.port,
		TLS:       adldap.TLSLDAPS,
		TLSConfig: &tls.Config{RootCAs: s.pool, ServerName: s.host, MinVersion: tls.VersionTLS12},
		Simple: &adldap.SimpleAuth{
			Username: bindDN,
			Password: adcore.NewSecret(bindPassword),
		},
		Timeout: 10 * time.Second,
	}
}

// Seed inserts an entry directly, bypassing the LDAP layer.
func (s *Server) Seed(dn string, attrs map[string][][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[dn] = attrs
}

// Entries returns a snapshot for assertions.
func (s *Server) Entries() map[string]map[string][][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[string][][]byte, len(s.entries))
	for dn, attrs := range s.entries {
		copied := make(map[string][][]byte, len(attrs))
		for k, v := range attrs {
			copied[k] = append([][]byte(nil), v...)
		}
		out[dn] = copied
	}
	return out
}

// waitForPort blocks until the server is accepting, so a test never races the
// listener's startup.
func waitForPort(t *testing.T, port int) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the harness never started listening on %s", addr)
}

// equalFoldDN compares two DNs the way AD does: case-insensitively, ignoring
// the optional space after a component separator.
func equalFoldDN(a, b string) bool {
	return strings.EqualFold(normalizeDN(a), normalizeDN(b))
}

func normalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
}

// isUnder reports whether dn sits beneath base, which is how the harness
// answers a subtree search.
func isUnder(dn, base string) bool {
	if equalFoldDN(dn, base) {
		return true
	}
	return strings.HasSuffix(strings.ToLower(normalizeDN(dn)), ","+strings.ToLower(normalizeDN(base)))
}

// isChildOf reports whether dn is an immediate child of base, for a one-level
// search.
func isChildOf(dn, base string) bool {
	if !isUnder(dn, base) || equalFoldDN(dn, base) {
		return false
	}
	rest := normalizeDN(dn)[:len(normalizeDN(dn))-len(normalizeDN(base))-1]
	return !strings.Contains(rest, ",")
}

// StartWire brings up the gldap-backed server and returns a Directory over it.
// It covers the go-ldap adapter and the socket; StartMemory covers the
// operations gldap cannot serve.
func StartWire(t *testing.T) adcore.Directory {
	t.Helper()
	srv := Start(t)
	client, err := adldap.New(context.Background(), srv.Config())
	if err != nil {
		t.Fatalf("adldap.New against the wire harness: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client.Directory()
}
