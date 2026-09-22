package attrs

import "strings"

// msDS-SupportedEncryptionTypes bits, per MS-KILE 2.2.7.
const (
	encDESCBCCRC uint32 = 1
	encDESCBCMD5 uint32 = 2
	encRC4       uint32 = 4
	encAES128    uint32 = 8
	encAES256    uint32 = 16
)

// encTypes is the canonical name for each bit, in bit order. The names are
// AD's own KerberosEncryptionType enum values, which is what the PowerShell
// backend emits — a different spelling here would show up as a permanent
// diff for anyone switching backends.
var encTypes = []struct {
	bit  uint32
	name string
}{
	{encDESCBCCRC, "DES-CBC-CRC"},
	{encDESCBCMD5, "DES-CBC-MD5"},
	{encRC4, "RC4"},
	{encAES128, "AES128"},
	{encAES256, "AES256"},
}

// EncTypeBits folds encryption-type names into the bitmask AD stores.
//
// The longer Kerberos spellings (RC4-HMAC-MD5, AES256-CTS-HMAC-SHA1-96) are
// accepted as well as the short AD ones, so a value read through either
// backend can be written to the other. A name that matches nothing
// contributes no bit: AD stores a mask, so an unknown name has no
// representation, and failing here would reject a configuration the
// PowerShell backend accepts.
func EncTypeBits(names []string) uint32 {
	var v uint32
	for _, n := range names {
		switch s := strings.ToUpper(strings.TrimSpace(n)); {
		case s == "DES-CBC-CRC":
			v |= encDESCBCCRC
		case s == "DES-CBC-MD5":
			v |= encDESCBCMD5
		case s == "RC4" || strings.HasPrefix(s, "RC4-HMAC"):
			v |= encRC4
		case strings.HasPrefix(s, "AES128"):
			v |= encAES128
		case strings.HasPrefix(s, "AES256"):
			v |= encAES256
		}
	}
	return v
}

// EncTypeNames is the inverse, in bit order so the list is stable across
// reads. Bits with no name here are dropped rather than rendered as a number:
// a caller cannot write back what it cannot name, and a synthetic name would
// not survive a round trip through the other backend.
func EncTypeNames(v uint32) []string {
	var out []string
	for _, e := range encTypes {
		if v&e.bit != 0 {
			out = append(out, e.name)
		}
	}
	return out
}
