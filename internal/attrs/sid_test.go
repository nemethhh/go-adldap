package attrs_test

import (
	"testing"

	"github.com/nemethhh/go-adldap/internal/attrs"
)

func TestSIDRoundTrip(t *testing.T) {
	for _, s := range []string{
		"S-1-1-0",      // Everyone
		"S-1-5-10",     // SELF
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-5-21-1585337133-390245860-2822598882-1105", // a domain account
		"S-1-5-21-1-2-3-512",                            // Domain Admins
	} {
		b, err := attrs.SIDFromString(s)
		if err != nil {
			t.Fatalf("SIDFromString(%q): %v", s, err)
		}
		back, err := attrs.SIDToString(b)
		if err != nil {
			t.Fatalf("SIDToString(%x): %v", b, err)
		}
		if back != s {
			t.Errorf("round trip of %q produced %q", s, back)
		}
	}
}

// The identifier authority is big-endian while the sub-authorities are
// little-endian. Writing both the same way produces a well-formed SID that
// names nothing, so the byte layout is asserted rather than only the round
// trip — which would pass with both directions wrong in the same way.
func TestSIDFromStringByteLayout(t *testing.T) {
	got, err := attrs.SIDFromString("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatalf("SIDFromString: %v", err)
	}
	want := []byte{
		1, 4, 0, 0, 0, 0, 0, 5, // revision 1, 4 sub-authorities, authority 5 big-endian
		21, 0, 0, 0,
		1, 0, 0, 0,
		2, 0, 0, 0,
		3, 0, 0, 0,
	}
	if string(got) != string(want) {
		t.Errorf("SIDFromString = %x, want %x", got, want)
	}
}

func TestSIDFromStringRejectsRubbish(t *testing.T) {
	for _, s := range []string{"", "nope", "S-1", "S-x-5-21", "S-1-5-notanumber"} {
		if _, err := attrs.SIDFromString(s); err == nil {
			t.Errorf("SIDFromString(%q) = nil error, want one", s)
		}
	}
}
