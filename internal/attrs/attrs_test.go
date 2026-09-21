package attrs_test

import (
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
)

// objectGUID is mixed-endian: the first three fields are little-endian, the
// last two big-endian. Reading it as a plain 16-byte big-endian UUID yields a
// plausible GUID that matches nothing — and the Terraform resource ID depends
// on it.
func TestGUIDRoundTripIsMixedEndian(t *testing.T) {
	raw := []byte{
		0x78, 0x56, 0x34, 0x12, // Data1, little-endian
		0x34, 0x12, // Data2, little-endian
		0x78, 0x56, // Data3, little-endian
		0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, // Data4, big-endian
	}
	got, err := attrs.GUIDToString(raw)
	if err != nil {
		t.Fatalf("GUIDToString: %v", err)
	}
	const want = "12345678-1234-5678-9abc-def011223344"
	if got != want {
		t.Fatalf("GUIDToString = %q, want %q", got, want)
	}

	back, err := attrs.GUIDToBytes(got)
	if err != nil {
		t.Fatalf("GUIDToBytes: %v", err)
	}
	if string(back) != string(raw) {
		t.Errorf("GUIDToBytes did not round-trip: % x, want % x", back, raw)
	}
}

func TestGUIDRejectsWrongLength(t *testing.T) {
	if _, err := attrs.GUIDToString([]byte{1, 2, 3}); err == nil {
		t.Fatal("a GUID that is not 16 bytes must be an error")
	}
}

func TestGUIDToBytesRejectsNonHex(t *testing.T) {
	if _, err := attrs.GUIDToBytes("zzzzzzzz-1234-5678-9abc-def011223344"); err == nil {
		t.Fatal("a GUID with non-hex characters must be an error")
	}
}

func TestSIDToString(t *testing.T) {
	// S-1-5-21-1-2-3
	raw := []byte{
		0x01,                               // revision
		0x04,                               // sub-authority count
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // identifier authority, big-endian
		0x15, 0x00, 0x00, 0x00, // 21
		0x01, 0x00, 0x00, 0x00, // 1
		0x02, 0x00, 0x00, 0x00, // 2
		0x03, 0x00, 0x00, 0x00, // 3
	}
	got, err := attrs.SIDToString(raw)
	if err != nil {
		t.Fatalf("SIDToString: %v", err)
	}
	if want := "S-1-5-21-1-2-3"; got != want {
		t.Errorf("SIDToString = %q, want %q", got, want)
	}
}

// The sub-authority count must agree with the length, or a truncated value
// would silently decode to a different, valid-looking SID.
func TestSIDRejectsInconsistentLength(t *testing.T) {
	raw := []byte{0x01, 0x04, 0, 0, 0, 0, 0, 5, 0x15, 0, 0, 0}
	if _, err := attrs.SIDToString(raw); err == nil {
		t.Fatal("a SID whose length disagrees with its sub-authority count must be an error")
	}
}

// accountExpires is a FILETIME string; 0 and 0x7FFFFFFFFFFFFFFF both mean
// "never", and a nil result is how that reaches the model.
func TestFileTimeNeverIsNil(t *testing.T) {
	for _, v := range []string{"0", "9223372036854775807"} {
		got, err := attrs.FileTimeToTime(v)
		if err != nil {
			t.Fatalf("FileTimeToTime(%q): %v", v, err)
		}
		if got != nil {
			t.Errorf("FileTimeToTime(%q) = %v, want nil for never", v, got)
		}
	}
}

func TestFileTimeRoundTrip(t *testing.T) {
	want := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	got, err := attrs.FileTimeToTime(attrs.TimeToFileTime(want))
	if err != nil {
		t.Fatalf("FileTimeToTime: %v", err)
	}
	if got == nil || !got.Equal(want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
}

// Scope and category are both carried by groupType. Deriving one without
// masking off the other's bits corrupts the other on write — the trap the
// PSOpenAD dialect records having found the hard way.
func TestGroupTypeCarriesBothScopeAndCategory(t *testing.T) {
	for _, tc := range []struct {
		scope    adcore.GroupScope
		category adcore.GroupCategory
	}{
		{adcore.GroupScopeGlobal, adcore.GroupCategorySecurity},
		{adcore.GroupScopeGlobal, adcore.GroupCategoryDistribution},
		{adcore.GroupScopeDomainLocal, adcore.GroupCategorySecurity},
		{adcore.GroupScopeDomainLocal, adcore.GroupCategoryDistribution},
		{adcore.GroupScopeUniversal, adcore.GroupCategorySecurity},
		{adcore.GroupScopeUniversal, adcore.GroupCategoryDistribution},
	} {
		v := attrs.GroupTypeValue(tc.scope, tc.category)
		gotScope, gotCategory := attrs.ScopeAndCategory(v)
		if gotScope != tc.scope || gotCategory != tc.category {
			t.Errorf("groupType %#x -> (%v, %v), want (%v, %v)",
				v, gotScope, gotCategory, tc.scope, tc.category)
		}
	}
}

// AD stores groupType as a signed 32-bit integer and LDAP carries it as its
// decimal string. A security group's high bit is set, so treating it as
// unsigned produces a value AD rejects.
func TestSecurityGroupTypeIsNegativeAsSigned(t *testing.T) {
	v := attrs.GroupTypeValue(adcore.GroupScopeGlobal, adcore.GroupCategorySecurity)
	if int32(v) >= 0 {
		t.Errorf("a security group's groupType should be negative as int32, got %d", int32(v))
	}
	if got := attrs.GroupTypeString(v); got != "-2147483646" {
		t.Errorf("GroupTypeString = %q, want the signed decimal AD accepts", got)
	}
}

// A groupType read off the wire arrives as that signed decimal, so parsing it
// as unsigned fails outright — and getting this wrong flips every security
// group to a distribution group on the next write.
func TestParseGroupTypeAcceptsTheSignedWireForm(t *testing.T) {
	v, err := attrs.ParseGroupType("-2147483646")
	if err != nil {
		t.Fatalf("ParseGroupType: %v", err)
	}
	scope, category := attrs.ScopeAndCategory(v)
	if scope != adcore.GroupScopeGlobal || category != adcore.GroupCategorySecurity {
		t.Errorf("got (%v, %v), want (global, security)", scope, category)
	}
}
