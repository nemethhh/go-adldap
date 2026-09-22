package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
)

// The AP-REQ must request mutual authentication. go-ldap's own GSSAPIBind
// helper sends no AP options while asking for ContextFlagMutual in the
// checksum, and Active Directory refuses that inconsistency with
// "AcceptSecurityContext error, data 57" — an ERROR_INVALID_PARAMETER that
// reads like a bad credential when the ticket is in fact perfect.
//
// There is no KDC in CI, so this guards the one thing that made the bind
// impossible: the option going missing again.
func TestAPOptionsRequestMutualAuthentication(t *testing.T) {
	got := apOptions()
	if len(got) == 0 {
		t.Fatal("no AP options; a bind with none is refused by AD with data 57")
	}
	for _, o := range got {
		if o == flags.APOptionMutualRequired {
			return
		}
	}
	t.Errorf("apOptions() = %v, want it to contain APOptionMutualRequired (%d)", got, flags.APOptionMutualRequired)
}

// The bind must present a channel-binding token derived from the certificate
// the connection actually negotiated. A binder that computed it from anything
// else — a configured hostname, a cached certificate — would bind to the wrong
// channel and be refused by exactly the domains this exists to support.
func TestBindDerivesTheTokenFromTheConnectionCertificate(t *testing.T) {
	_, leaf := newTestCA(t, "dc01.corp.local")

	got := KerberosBinder{Host: "dc01.corp.local"}.tokenForCertificate(leaf)
	want := channelBindingToken(leaf)

	if string(got) != string(want) {
		t.Errorf("token = % x, want the certificate's own % x", got, want)
	}
}

// tokenForCertificate is a pure helper: a nil certificate yields a nil token,
// never a token over a nil certificate. Bind itself is stricter — it treats a
// nil certificate (no TLS state on the connection) as a hard error rather
// than calling this helper and binding with no channel binding; see
// TestBindRefusesToBindWithNoPeerCertificate.
func TestNoCertificateYieldsNoToken(t *testing.T) {
	if got := (KerberosBinder{}).tokenForCertificate(nil); got != nil {
		t.Errorf("token = % x, want nil when there is no peer certificate", got)
	}
}

func TestBindRefusesToBindWithNoPeerCertificate(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	l := ldap.NewConn(client, false)

	err := (KerberosBinder{}).Bind(context.Background(), &goldapConn{l: l})
	if err == nil {
		t.Fatal("Bind must refuse a connection with no TLS state, not bind with no channel binding")
	}
	if !strings.Contains(err.Error(), "TLS is mandatory") {
		t.Errorf("error = %q, want it to say TLS is mandatory", err.Error())
	}
}

// Describe must name the mechanism without ever naming the credential.
func TestDescribeNeverLeaksAPassword(t *testing.T) {
	b := KerberosBinder{Username: "svc_tf", Realm: "CORP.LOCAL", Password: "hunter2"}
	if got := b.Describe(); strings.Contains(got, "hunter2") {
		t.Fatalf("Describe() leaked the password: %q", got)
	}
}

// peerCertificate is what Bind actually calls to read the certificate off the
// connection. Pinning it directly, rather than only through
// tokenForCertificate, is what catches a future refactor that sources the
// certificate from configuration instead of the live handshake.
func TestPeerCertificateReturnsTheLeaf(t *testing.T) {
	_, leaf := newTestCA(t, "dc01.corp.local")

	got := peerCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, true)
	if got != leaf {
		t.Errorf("peerCertificate = %v, want the connection's leaf certificate", got)
	}
}

func TestPeerCertificateWithoutTLSStateReturnsNil(t *testing.T) {
	_, leaf := newTestCA(t, "dc01.corp.local")

	if got := peerCertificate(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, false); got != nil {
		t.Errorf("peerCertificate = %v, want nil when TLSConnectionState reports ok == false", got)
	}
}

func TestPeerCertificateWithNoCertificatesReturnsNil(t *testing.T) {
	if got := peerCertificate(tls.ConnectionState{}, true); got != nil {
		t.Errorf("peerCertificate = %v, want nil when the connection carries no peer certificates", got)
	}
}
