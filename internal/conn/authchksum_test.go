package conn

import (
	"bytes"
	"testing"

	"github.com/oiweiwei/gokrb5.fork/v9/gssapi"
	"github.com/oiweiwei/gokrb5.fork/v9/iana/flags"
)

// The 24 bytes of RFC 4121 4.1.1, asserted literally. Every byte here is a
// position a domain controller reads, and the checksum is not self-describing:
// a field in the wrong place fails as an opaque refusal, never as a parse
// error.
func TestAuthenticatorChecksumLayoutWithoutChannelBinding(t *testing.T) {
	got := authenticatorChecksum([]int{flags.APOptionMutualRequired}, nil)
	want := []byte{
		16, 0, 0, 0, // Lgth: always 16, little-endian
		0, 0, 0, 0, 0, 0, 0, 0, // Bnd: 16 zero bytes when unbound
		0, 0, 0, 0, 0, 0, 0, 0,
		2, 0, 0, 0, // Flags, little-endian
	}
	if !bytes.Equal(got, want) {
		t.Errorf("authenticatorChecksum() = % x, want % x", got, want)
	}
}

// The regression guard for this whole change. With no channel binding the
// bytes must be exactly what the library produced before we owned this
// function, or a domain at enforcement 0 or 1 that works today would start
// failing.
func TestChecksumWithoutBindingIsUnchangedFromTheLibrary(t *testing.T) {
	got := authenticatorChecksum(
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}, nil)

	if len(got) != 24 {
		t.Fatalf("length = %d, want 24", len(got))
	}
	for i, b := range got[4:20] {
		if b != 0 {
			t.Errorf("Bnd[%d] = %d, want 0 when no channel binding is supplied", i, b)
		}
	}
	want := []byte{16, 0, 0, 0}
	if !bytes.Equal(got[:4], want) {
		t.Errorf("Lgth = % x, want % x", got[:4], want)
	}
	// Integ(32) | Conf(16) | Mutual(2) == 50 == 0x32
	if got[20] != 50 || got[21] != 0 || got[22] != 0 || got[23] != 0 {
		t.Errorf("Flags = % x, want 32 00 00 00 (50 little-endian)", got[20:24])
	}
}

// The token lands in Bnd and nowhere else; Lgth stays 16 regardless.
func TestChecksumCarriesTheChannelBindingToken(t *testing.T) {
	bnd := []byte{
		0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
		5, 6, 7, 8, 9, 10, 11, 12,
	}
	got := authenticatorChecksum([]int{flags.APOptionMutualRequired}, bnd)

	if !bytes.Equal(got[4:20], bnd) {
		t.Errorf("Bnd = % x, want % x", got[4:20], bnd)
	}
	if !bytes.Equal(got[:4], []byte{16, 0, 0, 0}) {
		t.Errorf("Lgth = % x, want 10 00 00 00; it is fixed at 16 even when bound", got[:4])
	}
	if got[20] != 2 {
		t.Errorf("Flags = % x, want the flag preserved alongside the binding", got[20:24])
	}
}

// Delegation widens the checksum to 28 bytes. Unused by this library today,
// but getting it wrong would corrupt the four bytes that follow.
func TestDelegationWidensTheChecksum(t *testing.T) {
	got := authenticatorChecksum([]int{gssapi.ContextFlagDeleg}, nil)
	if len(got) != 28 {
		t.Errorf("length = %d, want 28 when ContextFlagDeleg is set", len(got))
	}
}

// A token that is not 16 bytes would silently shift every later field.
func TestChecksumRejectsAWrongSizedToken(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a short channel-binding token was accepted; it would corrupt the Flags field")
		}
	}()
	authenticatorChecksum(nil, []byte{1, 2, 3})
}
