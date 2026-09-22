package conn

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// The gss_channel_bindings_struct layout is four zero uint32s followed by a
// length-prefixed application_data, all little-endian. Asserting the literal
// bytes is the only way to catch a field-order or endianness regression; the
// MD5 that follows would hide one.
func TestChannelBindingStructLayout(t *testing.T) {
	got := channelBindingStruct([]byte("abc"))
	want := []byte{
		0, 0, 0, 0, // initiator address type
		0, 0, 0, 0, // initiator address length
		0, 0, 0, 0, // acceptor address type
		0, 0, 0, 0, // acceptor address length
		3, 0, 0, 0, // application_data length, little-endian
		'a', 'b', 'c',
	}
	if !bytes.Equal(got, want) {
		t.Errorf("channelBindingStruct() = % x, want % x", got, want)
	}
}

// The token is MD5 over that struct, with application_data being the RFC 5929
// prefix and the certificate hash. Built here from the primitives rather than
// by calling the implementation, so the test fails if the implementation
// changes shape.
func TestChannelBindingTokenIsMD5OverPrefixedCertHash(t *testing.T) {
	_, leaf := newTestCA(t, "dc01.corp.local")

	sum := sha256.Sum256(leaf.Raw)
	appData := append([]byte("tls-server-end-point:"), sum[:]...)
	expect := md5.Sum(channelBindingStruct(appData))

	got := channelBindingToken(leaf)
	if len(got) != 16 {
		t.Fatalf("token length = %d, want 16 (the Bnd field is fixed width)", len(got))
	}
	if !bytes.Equal(got, expect[:]) {
		t.Errorf("channelBindingToken() = % x, want % x", got, expect[:])
	}
}

// A different certificate must produce a different token, or channel binding
// would bind nothing.
func TestChannelBindingTokenIsCertificateSpecific(t *testing.T) {
	_, a := newTestCA(t, "dc01.corp.local")
	_, b := newTestCA(t, "dc02.corp.local")

	if bytes.Equal(channelBindingToken(a), channelBindingToken(b)) {
		t.Error("two certificates produced the same token; the binding is not to the certificate")
	}
}

// RFC 5929 4.1: the certificate's own signature hash is used, except that
// MD5 and SHA-1 promote to SHA-256. newTestCA signs with SHA-256, so the
// promotion arms are asserted through the selector directly.
func TestCertificateHashSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  x509.SignatureAlgorithm
		size int
	}{
		{"sha1 promotes to sha256", x509.SHA1WithRSA, 32},
		{"sha256 stays sha256", x509.SHA256WithRSA, 32},
		{"sha384 keeps its size", x509.SHA384WithRSA, 48},
		{"ecdsa sha384 keeps its size", x509.ECDSAWithSHA384, 48},
		{"sha512 keeps its size", x509.SHA512WithRSA, 64},
		{"rsapss sha512 keeps its size", x509.SHA512WithRSAPSS, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := certificateHash(tc.alg).Size(); got != tc.size {
				t.Errorf("certificateHash(%v).Size() = %d, want %d", tc.alg, got, tc.size)
			}
		})
	}
}
