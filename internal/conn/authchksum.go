package conn

import (
	"encoding/binary"
	"fmt"

	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
)

// channelBindingLen is the width of the Bnd field. RFC 4121 4.1.1.2 fixes it
// at the size of an MD5 digest.
const channelBindingLen = 16

// authenticatorChecksum builds the GSSAPI checksum of RFC 4121 4.1.1, which
// rides in the AP-REQ authenticator:
//
//	[0:4]   Lgth  — always 16, little-endian
//	[4:20]  Bnd   — the channel-binding token, or 16 zero bytes
//	[20:24] Flags — the context flags, OR-ed, little-endian
//	[24:28] DlgOpt and Dlgth, present only with ContextFlagDeleg
//
// No Kerberos library for Go exposes this. gokrb5 and its fork both build it
// internally with Bnd hardcoded to zero and offer no way to set it, which is
// why a bind from this library is refused by a domain controller with
// LdapEnforceChannelBinding = 2. Owning the function is the whole reason this
// package implements ldap.GSSAPIClient itself.
//
// Lgth stays 16 whether or not a token is present: it is the length of the Bnd
// field, not of the data bound.
func authenticatorChecksum(contextFlags []int, bnd []byte) []byte {
	if bnd != nil && len(bnd) != channelBindingLen {
		panic(fmt.Sprintf(
			"adldap: channel-binding token is %d bytes, must be %d; "+
				"a wrong width shifts every later checksum field",
			len(bnd), channelBindingLen))
	}

	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b[:4], channelBindingLen)
	copy(b[4:20], bnd)

	var f uint32
	for _, flag := range contextFlags {
		if flag == gssapi.ContextFlagDeleg {
			// DlgOpt and Dlgth follow the flags when delegation is asked for.
			b = append(b, make([]byte, 28-len(b))...)
		}
		f |= uint32(flag)
	}
	binary.LittleEndian.PutUint32(b[20:24], f)

	return b
}
