package conn

import (
	"bytes"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/etypeID"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/nametype"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// go-ldap accepts any GSSAPIClient. If the method set drifts, the failure is
// a compile error here rather than at the one call site in bind_krb.go.
func TestGSSClientSatisfiesTheGoLDAPInterface(t *testing.T) {
	var _ ldap.GSSAPIClient = (*gssClient)(nil)
}

// A client built with a token must carry it into the checksum, and one built
// without must produce the bytes the library produced before this package
// owned the function. Asserted through the checksum rather than through a
// bind, because a bind needs a KDC.
func TestGSSClientChecksumCarriesItsChannelBinding(t *testing.T) {
	bnd := make([]byte, 16)
	for i := range bnd {
		bnd[i] = byte(i + 1)
	}

	bound := newGSSClient(nil, bnd)
	if got := bound.checksum(); string(got[4:20]) != string(bnd) {
		t.Errorf("Bnd = % x, want % x", got[4:20], bnd)
	}

	unbound := newGSSClient(nil, nil)
	got := unbound.checksum()
	for i, b := range got[4:20] {
		if b != 0 {
			t.Fatalf("Bnd[%d] = %d, want 0; an unbound client must send what the library used to", i, b)
		}
	}
}

// The context flags are what AD expects from a SASL GSSAPI initiator. Losing
// one of them is refused with a message that names none of them.
func TestGSSClientRequestsIntegrityConfidentialityAndMutualAuth(t *testing.T) {
	got := newGSSClient(nil, nil).checksum()
	// Integ(32) | Conf(16) | Mutual(2) == 50
	if got[20] != 50 {
		t.Errorf("flags byte = %d, want 50 (Integ|Conf|Mutual)", got[20])
	}
}

// The end-to-end proof that the channel binding survives into the bytes a
// domain controller reads. Everything above tests a field in isolation; this
// marshals a real MechToken, reads it back through the library's own parser,
// decrypts the authenticator and finds the token in Bnd.
//
// It needs no KDC: NewWithPassword builds a client without contacting one, and
// the ticket and session key are synthetic. What is exercised is the encoding,
// which is where the bugs are.
func TestAPREQCarriesTheChannelBindingOnTheWire(t *testing.T) {
	cfg, err := loadKrb5Conf("", "CORP.LOCAL", "dc01.corp.local", statMissing)
	if err != nil {
		t.Fatalf("loadKrb5Conf: %v", err)
	}
	cl := client.NewWithPassword("svc_tf", "CORP.LOCAL", "hunter2", cfg)

	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: make([]byte, 32),
	}
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "CORP.LOCAL",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{"ldap", "dc01.corp.local"},
		},
	}

	bnd := make([]byte, 16)
	for i := range bnd {
		bnd[i] = byte(0xa0 + i)
	}

	c := newGSSClient(&gokrb5Source{cl: cl}, bnd)
	token, err := c.newAPREQToken(tkt, key, []int{flags.APOptionMutualRequired})
	if err != nil {
		t.Fatalf("newAPREQToken: %v", err)
	}
	wire, err := token.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var back spnego.KRB5Token
	if err := back.Unmarshal(wire); err != nil {
		t.Fatalf("the MechToken we produced did not parse: %v", err)
	}
	if back.IsAPRep() || back.IsKRBError() {
		t.Fatal("token is not an AP-REQ")
	}

	plain, err := crypto.DecryptEncPart(back.APReq.EncryptedAuthenticator, key, keyusage.AP_REQ_AUTHENTICATOR)
	if err != nil {
		t.Fatalf("decrypting the authenticator: %v", err)
	}
	var auth types.Authenticator
	if err := auth.Unmarshal(plain); err != nil {
		t.Fatalf("reading the authenticator: %v", err)
	}

	if auth.Cksum.CksumType != chksumtype.GSSAPI {
		t.Errorf("checksum type = %d, want %d (GSSAPI)", auth.Cksum.CksumType, chksumtype.GSSAPI)
	}
	if len(auth.Cksum.Checksum) < 24 {
		t.Fatalf("checksum is %d bytes, want at least 24", len(auth.Cksum.Checksum))
	}
	if !bytes.Equal(auth.Cksum.Checksum[4:20], bnd) {
		t.Errorf("Bnd on the wire = % x, want % x", auth.Cksum.Checksum[4:20], bnd)
	}
}
