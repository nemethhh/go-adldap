// Package attrs encodes and decodes the Active Directory attribute values the
// cmdlets used to hide.
//
// Every synthetic property the ActiveDirectory module exposes — Enabled,
// PasswordNeverExpires, GroupScope, GroupCategory, AccountExpirationDate — is
// a bit or a FILETIME in a real attribute. The reference implementation for
// all of this is go-adpwsh's internal/adscript/ops_psopenad/preamble.ps1,
// which does the same work over LDAP and records the traps in comments.
package attrs

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nemethhh/go-adcore"
)

// GUIDToString formats an objectGUID. The layout is mixed-endian: Data1,
// Data2 and Data3 are little-endian, Data4 is big-endian. Reading all sixteen
// bytes as a big-endian UUID produces a well-formed GUID that matches nothing,
// and the Terraform resource ID is built from this.
func GUIDToString(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("attrs: objectGUID is %d bytes, want 16", len(b))
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	), nil
}

// GUIDToBytes is the inverse of GUIDToString.
func GUIDToBytes(s string) ([]byte, error) {
	hexs := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(hexs) != 32 {
		return nil, fmt.Errorf("attrs: %q is not a GUID", s)
	}
	var flat [16]byte
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(hexs[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("attrs: %q is not a GUID: %w", s, err)
		}
		flat[i] = byte(v)
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], binary.BigEndian.Uint32(flat[0:4]))
	binary.LittleEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(flat[4:6]))
	binary.LittleEndian.PutUint16(out[6:8], binary.BigEndian.Uint16(flat[6:8]))
	copy(out[8:16], flat[8:16])
	return out, nil
}

// SIDToString formats an objectSid per MS-DTYP 2.4.2.
func SIDToString(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("attrs: objectSid is %d bytes, too short", len(b))
	}
	revision := b[0]
	subCount := int(b[1])
	if len(b) != 8+4*subCount {
		return "", fmt.Errorf("attrs: objectSid is %d bytes, want %d for %d sub-authorities",
			len(b), 8+4*subCount, subCount)
	}
	var authority uint64
	for _, x := range b[2:8] { // big-endian, six bytes
		authority = authority<<8 | uint64(x)
	}
	sb := &strings.Builder{}
	fmt.Fprintf(sb, "S-%d-%d", revision, authority)
	for i := 0; i < subCount; i++ {
		fmt.Fprintf(sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:12+4*i]))
	}
	return sb.String(), nil
}

// FileTimeNever is the accountExpires value meaning "never expires". AD also
// uses 0 for the same thing.
const FileTimeNever int64 = 0x7FFFFFFFFFFFFFFF

// fileTimeEpochOffset is the number of 100-nanosecond intervals between the
// FILETIME epoch (1601-01-01) and the Unix epoch.
const fileTimeEpochOffset int64 = 116444736000000000

// FileTimeToTime decodes a FILETIME attribute. A nil result means "never",
// which is what both 0 and FileTimeNever encode.
func FileTimeToTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("attrs: %q is not a FILETIME: %w", s, err)
	}
	if v == 0 || v == FileTimeNever {
		return nil, nil
	}
	t := time.Unix(0, (v-fileTimeEpochOffset)*100).UTC()
	return &t, nil
}

// TimeToFileTime encodes a time as a FILETIME attribute value.
func TimeToFileTime(t time.Time) string {
	return strconv.FormatInt(t.UTC().UnixNano()/100+fileTimeEpochOffset, 10)
}

// userAccountControl bits, per MS-ADTS 2.2.16.
const (
	UACAccountDisable     uint32 = 0x0002
	UACNormalAccount      uint32 = 0x0200
	UACDontExpirePassword uint32 = 0x10000
	// UACWorkstationTrustAccount is what a computer or gMSA account carries
	// where a user carries UACNormalAccount. Creating a computer with
	// UACNormalAccount produces an object AD will not authenticate.
	UACWorkstationTrustAccount uint32 = 0x1000
	// UACTrustedForDelegation is unconstrained delegation. It is a bit on the
	// account, not a separate attribute, which is why TrustedForDelegation
	// reads and writes through userAccountControl on both classes.
	UACTrustedForDelegation uint32 = 0x80000
)

// groupType bits, per MS-ADTS 2.2.12. These are uint32 constants: AD stores
// groupType as a signed 32-bit integer and LDAP carries it as its decimal
// string, so a security group — whose high bit is set — must be formatted from
// the signed value or AD rejects it.
const (
	GroupTypeSystem      uint32 = 0x00000001
	GroupTypeGlobal      uint32 = 0x00000002
	GroupTypeDomainLocal uint32 = 0x00000004
	GroupTypeUniversal   uint32 = 0x00000008
	GroupTypeSecurity    uint32 = 0x80000000

	groupTypeScopeMask uint32 = GroupTypeGlobal | GroupTypeDomainLocal | GroupTypeUniversal
)

// ScopeAndCategory derives both properties from groupType. They share one
// field, so a write that sets one must preserve the other's bits — deriving
// scope by switching on the whole value silently changes the category.
func ScopeAndCategory(v uint32) (adcore.GroupScope, adcore.GroupCategory) {
	category := adcore.GroupCategoryDistribution
	if v&GroupTypeSecurity != 0 {
		category = adcore.GroupCategorySecurity
	}
	var scope adcore.GroupScope
	switch v & groupTypeScopeMask {
	case GroupTypeDomainLocal:
		scope = adcore.GroupScopeDomainLocal
	case GroupTypeUniversal:
		scope = adcore.GroupScopeUniversal
	default:
		scope = adcore.GroupScopeGlobal
	}
	return scope, category
}

// GroupTypeValue builds groupType from both properties.
func GroupTypeValue(scope adcore.GroupScope, category adcore.GroupCategory) uint32 {
	var v uint32
	switch scope {
	case adcore.GroupScopeDomainLocal:
		v |= GroupTypeDomainLocal
	case adcore.GroupScopeUniversal:
		v |= GroupTypeUniversal
	default:
		v |= GroupTypeGlobal
	}
	if category != adcore.GroupCategoryDistribution {
		v |= GroupTypeSecurity
	}
	return v
}

// GroupTypeString formats groupType for the wire: from the signed value, so a
// security group's high bit becomes a negative decimal rather than one AD
// rejects.
func GroupTypeString(v uint32) string {
	return strconv.FormatInt(int64(int32(v)), 10)
}

// ParseGroupType reads groupType off the wire. It parses signed, because that
// is what AD sends: a security group arrives as a negative decimal, and
// parsing unsigned fails outright — which, handled leniently, would flip every
// security group to a distribution group on the next write.
func ParseGroupType(s string) (uint32, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("attrs: %q is not a groupType: %w", s, err)
	}
	return uint32(int32(v)), nil
}

// ParseUint32 reads a decimal attribute such as userAccountControl. It parses
// signed for the same reason ParseGroupType does.
func ParseUint32(s string) (uint32, error) {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("attrs: %q is not an integer attribute: %w", s, err)
	}
	return uint32(int32(v)), nil
}

// Uint32String formats an integer attribute for the wire, signed.
func Uint32String(v uint32) string { return strconv.FormatInt(int64(int32(v)), 10) }
