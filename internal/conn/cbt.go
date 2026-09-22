package conn

import (
	"crypto"
	"crypto/md5" //nolint:gosec // RFC 4121 4.1.1.2 mandates MD5 for the Bnd field.
	"crypto/x509"
	"encoding/binary"

	_ "crypto/sha256" // registers the hashes crypto.Hash.New needs
	_ "crypto/sha512"
)

// channelBindingToken builds the tls-server-end-point token of RFC 5929 4.1
// and returns the 16 bytes that go in the Bnd field of the RFC 4121 4.1.1
// authenticator checksum.
//
// This is what a domain with LdapEnforceChannelBinding = 2 requires and what
// its absence causes to be refused as "data 80090346" — a message that names
// neither channel binding nor Kerberos.
//
// MD5 is not a security choice here. RFC 4121 4.1.1.2 fixes the algorithm for
// this field, the hash is not a credential, and substituting anything else
// would simply fail to authenticate.
func channelBindingToken(cert *x509.Certificate) []byte {
	h := certificateHash(cert.SignatureAlgorithm).New()
	h.Write(cert.Raw)

	appData := append([]byte("tls-server-end-point:"), h.Sum(nil)...)
	sum := md5.Sum(channelBindingStruct(appData))
	return sum[:]
}

// certificateHash picks the digest RFC 5929 4.1 requires: the one the
// certificate was signed with, except that MD5 and SHA-1 are too weak and
// promote to SHA-256. Returning SHA-256 for anything unrecognised is the same
// rule, since an unknown algorithm is not one of the two wider families.
func certificateHash(alg x509.SignatureAlgorithm) crypto.Hash {
	switch alg {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// channelBindingStruct marshals the gss_channel_bindings_struct of RFC 2744,
// which Windows documents as SEC_CHANNEL_BINDINGS. Both addresses are absent,
// which is what every TLS channel binding does: the binding is to the
// certificate, not to an address.
//
// Kept separate from the hashing so its byte layout can be asserted directly.
// An MD5 over a wrong layout is indistinguishable from an MD5 over a right
// one until a domain controller refuses the bind.
func channelBindingStruct(appData []byte) []byte {
	b := make([]byte, 0, 20+len(appData))
	b = binary.LittleEndian.AppendUint32(b, 0) // initiator address type
	b = binary.LittleEndian.AppendUint32(b, 0) // initiator address length
	b = binary.LittleEndian.AppendUint32(b, 0) // acceptor address type
	b = binary.LittleEndian.AppendUint32(b, 0) // acceptor address length
	b = binary.LittleEndian.AppendUint32(b, uint32(len(appData)))
	return append(b, appData...)
}
