package attrs_test

import (
	"reflect"
	"testing"

	"github.com/nemethhh/go-adldap/internal/attrs"
)

func TestEncTypeBits(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  uint32
	}{
		{"none", nil, 0},
		{"rc4", []string{"RC4"}, 4},
		{"aes pair", []string{"AES128", "AES256"}, 8 | 16},
		// The long Kerberos spellings are what a user may paste from a KDC
		// document; accepting them is what lets a value round-trip between
		// the two backends.
		{"long spellings", []string{"RC4-HMAC-MD5", "AES256-CTS-HMAC-SHA1-96"}, 4 | 16},
		{"case and space insensitive", []string{"  aes128  "}, 8},
		{"legacy des", []string{"DES-CBC-CRC", "DES-CBC-MD5"}, 1 | 2},
		// An unknown name contributes nothing rather than failing: AD itself
		// stores a bitmask, so a name it does not know cannot be represented
		// and silently dropping it matches what the PowerShell backend does.
		{"unknown", []string{"AES256", "NOT-A-CIPHER"}, 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := attrs.EncTypeBits(tc.names); got != tc.want {
				t.Errorf("EncTypeBits(%v) = %d, want %d", tc.names, got, tc.want)
			}
		})
	}
}

func TestEncTypeNames(t *testing.T) {
	cases := []struct {
		name string
		v    uint32
		want []string
	}{
		{"none", 0, nil},
		{"rc4", 4, []string{"RC4"}},
		// Order is bit order, ascending, so two reads of the same value always
		// produce the same list and Terraform sees no diff.
		{"aes pair", 8 | 16, []string{"AES128", "AES256"}},
		{"all five", 1 | 2 | 4 | 8 | 16, []string{"DES-CBC-CRC", "DES-CBC-MD5", "RC4", "AES128", "AES256"}},
		// Bits AD may set that have no name here are dropped, not guessed at.
		{"unknown bit", 16 | 0x40000000, []string{"AES256"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := attrs.EncTypeNames(tc.v); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("EncTypeNames(%d) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}
}

func TestEncTypeRoundTrip(t *testing.T) {
	in := []string{"AES128", "AES256", "RC4"}
	got := attrs.EncTypeNames(attrs.EncTypeBits(in))
	want := []string{"RC4", "AES128", "AES256"} // bit order
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip = %v, want %v", got, want)
	}
}
