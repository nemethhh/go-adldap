package conn

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/oiweiwei/gokrb5.fork/v9/crypto"
	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/chksumtype"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/keyusage"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// gssClient implements go-ldap's ldap.GSSAPIClient over a ticketSource.
//
// go-ldap ships such a client already, in its gssapi sub-package, and this
// package used it until channel binding was needed. That one builds the
// authenticator through the Kerberos library's own constructor, which
// hardcodes the Bnd field to zero — so a bind from it is refused outright by a
// domain controller with LdapEnforceChannelBinding = 2. The interface is
// bytes in and bytes out, so implementing it here costs little and buys both
// the channel binding and a free choice of Kerberos library.
//
// Adapted from github.com/RedTeamPentesting/adauth (MIT), which solved the
// same problem first.
type gssClient struct {
	src ticketSource
	// cbt is the 16-byte tls-server-end-point token, or nil when the
	// connection carries no peer certificate to bind to.
	cbt []byte

	// ekey is the service ticket's session key and subkey the one the
	// acceptor returns in its AP-REP. Both are needed to verify and build the
	// wrapped tokens of the final SASL exchange.
	ekey   types.EncryptionKey
	subkey types.EncryptionKey
}

func newGSSClient(src ticketSource, cbt []byte) *gssClient {
	return &gssClient{src: src, cbt: cbt}
}

// contextFlags are what a SASL GSSAPI initiator asks Active Directory for.
// They also go in the checksum, where they must agree with the AP options —
// the disagreement that produces "AcceptSecurityContext error, data 57".
func contextFlags() []int {
	return []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}
}

// checksum is the authenticator checksum this client will send. Split out so
// it can be asserted without a KDC.
func (c *gssClient) checksum() []byte {
	return authenticatorChecksum(contextFlags(), c.cbt)
}

func (c *gssClient) Close() error { c.src.Destroy(); return nil }

// DeleteSecContext drops the session keys. It does not destroy the credential
// — Close does that — because go-ldap calls this at the end of a bind while
// the Binder must stay reusable for the pool's reconnect.
func (c *gssClient) DeleteSecContext() error {
	c.ekey = types.EncryptionKey{}
	c.subkey = types.EncryptionKey{}
	return nil
}

func (c *gssClient) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, input, []int{flags.APOptionMutualRequired})
}

// InitSecContextWithOptions runs the two halves of RFC 4752 section 3.1: the
// AP-REQ out, then the acceptor's AP-REP back.
func (c *gssClient) InitSecContextWithOptions(target string, input []byte, apOptions []int) ([]byte, bool, error) {
	if input == nil {
		tkt, ekey, err := c.src.ServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		c.ekey = ekey

		token, err := c.newAPREQToken(tkt, ekey, apOptions)
		if err != nil {
			return nil, false, err
		}
		out, err := token.Marshal()
		if err != nil {
			return nil, false, fmt.Errorf("adldap: marshalling the AP-REQ: %w", err)
		}
		return out, true, nil
	}

	var token spnego.KRB5Token
	if err := token.Unmarshal(input); err != nil {
		return nil, false, fmt.Errorf("adldap: reading the acceptor's token: %w", err)
	}

	if token.IsKRBError() {
		return nil, false, token.KRBError
	}

	var completed bool
	if token.IsAPRep() {
		completed = true
		encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, c.ekey, keyusage.AP_REP_ENCPART)
		if err != nil {
			return nil, false, fmt.Errorf("adldap: decrypting the AP-REP: %w", err)
		}
		part := &messages.EncAPRepPart{}
		if err := part.Unmarshal(encpart); err != nil {
			return nil, false, fmt.Errorf("adldap: reading the AP-REP: %w", err)
		}
		c.subkey = part.Subkey
	}

	return []byte{}, !completed, nil
}

// newAPREQToken builds the MechToken carrying our authenticator.
//
// spnego.KRB5Token's token-id field is unexported and its Marshal refuses to
// run without it, so a token cannot be built from a literal. The library's
// constructor is called for the sole purpose of getting one with that field
// set; the AP-REQ it produces is thrown away and replaced with ours, which is
// the same message but for an authenticator checksum carrying the channel
// binding.
func (c *gssClient) newAPREQToken(tkt messages.Ticket, ekey types.EncryptionKey, apOptions []int) (*spnego.KRB5Token, error) {
	token, err := spnego.NewKRB5TokenAPREQ(c.src.Client(), tkt, ekey, contextFlags(), apOptions)
	if err != nil {
		return nil, err
	}

	auth, err := types.NewAuthenticator(c.src.Realm(), c.src.CName())
	if err != nil {
		return nil, fmt.Errorf("adldap: building the authenticator: %w", err)
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  c.checksum(),
	}

	apReq, err := messages.NewAPReq(tkt, ekey, auth)
	if err != nil {
		return nil, fmt.Errorf("adldap: building the AP-REQ: %w", err)
	}
	for _, o := range apOptions {
		types.SetFlag(&apReq.APOptions, o)
	}

	token.APReq = apReq
	return &token, nil
}

// NegotiateSaslAuth is the last step of RFC 4752 section 3.1: the acceptor
// wraps its offered security layers, and the initiator answers with the one it
// picked.
//
// No security layer is selected. TLS already protects this connection — the
// package has no plain mode — and asking for GSSAPI sign or seal on top would
// add a second encryption layer for nothing.
func (c *gssClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &gssapi.WrapToken{}
	if err := unmarshalWrapToken(token, input, true); err != nil {
		return nil, err
	}
	if token.Flags&0b1 == 0 {
		return nil, errors.New("adldap: the wrapped token did not come from the acceptor")
	}

	key := c.ekey
	if token.Flags&0b100 != 0 {
		key = c.subkey
	}
	if _, err := token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		return nil, fmt.Errorf("adldap: verifying the acceptor's token: %w", err)
	}
	if len(token.Payload) != 4 {
		return nil, fmt.Errorf("adldap: the acceptor's final token is %d bytes, want 4", len(token.Payload))
	}

	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	reply := &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(etype.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   append([]byte{0, 0, 0, 0}, []byte(authzid)...),
	}
	if err := reply.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}
	return reply.Marshal()
}

// unmarshalWrapToken reads a GSSAPI Wrap token (RFC 4121 4.2.6.2) from the
// wire.
//
// Copied from github.com/go-ldap/ldap/v3@v3.4.14/gssapi/client.go, where it is
// exported as UnmarshalWrapToken, because the Kerberos library's own
// WrapToken.Unmarshal rejects the acceptor's final SASL token — go-ldap wrote
// its own reader for exactly this reason, and this package needs that reader
// without importing go-ldap's gssapi sub-package (which pulls in
// jcmturner/gokrb5 instead of the fork this package uses). Ported verbatim
// but for the gssapi import, which now points at the fork.
func getGssWrapTokenId() *[2]byte {
	return &[2]byte{0x05, 0x04}
}

func unmarshalWrapToken(wt *gssapi.WrapToken, b []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(b) < 16 {
		return errors.New("bytes shorter than header length")
	}
	// Is the Token ID correct?
	if !bytes.Equal(getGssWrapTokenId()[:], b[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(getGssWrapTokenId()[:]),
			hex.EncodeToString(b[0:2]))
	}
	// Check the acceptor flag
	wtflags := b[2]
	isFromAcceptor := wtflags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}
	// Check the filler byte
	if b[3] != gssapi.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(b[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(b[4:6])
	// Sanity check on the checksum length
	if int(checksumL) > len(b)-gssapi.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(b), checksumL)
	}

	// Compute the offset in int. checksumL is a uint16 read from the wire, so
	// 16 + checksumL overflows the uint16 range once checksumL exceeds 65519,
	// wrapping to a small value and turning the slices below into out-of-range
	// accesses that panic the bind goroutine.
	payloadStart := gssapi.HdrLen + int(checksumL)

	wt.Flags = wtflags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(b[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(b[8:16])
	wt.CheckSum = b[16:payloadStart]
	wt.Payload = b[payloadStart:]

	return nil
}
