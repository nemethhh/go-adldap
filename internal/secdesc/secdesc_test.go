package secdesc

import (
	"encoding/binary"
	"testing"
)

// buildSD assembles a self-relative descriptor with the given DACL entries,
// so the tests start from something a directory could actually return.
func buildSD(t *testing.T, aceList [][]byte) []byte {
	t.Helper()
	dacl := buildACL(2, aceList)
	p := &parsed{revision: 1, control: controlSelfRel | controlDACLPresent, dacl: dacl}
	return p.serialize()
}

// allowACE is an opaque third-party entry: this package must carry it through
// untouched without understanding it.
func allowACE(mask uint32, sid []byte) []byte {
	ace := make([]byte, aceHeaderLen+4+len(sid))
	ace[0] = 0x00 // ACCESS_ALLOWED_ACE
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

var someSID = []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0}

func TestSetProtectedRoundTrip(t *testing.T) {
	sd := buildSD(t, [][]byte{allowACE(0x000F01FF, someSID)})

	on, err := IsProtected(sd)
	if err != nil {
		t.Fatalf("IsProtected: %v", err)
	}
	if on {
		t.Fatal("a fresh descriptor must not report protected")
	}

	protected, changed, err := SetProtected(sd, true)
	if err != nil {
		t.Fatalf("SetProtected(true): %v", err)
	}
	if !changed {
		t.Fatal("adding protection should report a change")
	}
	if on, err = IsProtected(protected); err != nil || !on {
		t.Fatalf("IsProtected after adding = %v, %v", on, err)
	}

	back, changed, err := SetProtected(protected, false)
	if err != nil {
		t.Fatalf("SetProtected(false): %v", err)
	}
	if !changed {
		t.Fatal("removing protection should report a change")
	}
	if on, err = IsProtected(back); err != nil || on {
		t.Fatalf("IsProtected after removing = %v, %v", on, err)
	}
}

// Writing the same state twice must not rewrite the descriptor: a no-op write
// of nTSecurityDescriptor is a replication-generating change for nothing.
func TestSetProtectedIsIdempotent(t *testing.T) {
	sd := buildSD(t, nil)
	on, _, err := SetProtected(sd, true)
	if err != nil {
		t.Fatalf("SetProtected: %v", err)
	}
	if _, changed, err := SetProtected(on, true); err != nil || changed {
		t.Errorf("second SetProtected(true) changed=%v err=%v, want no change", changed, err)
	}
	if _, changed, err := SetProtected(sd, false); err != nil || changed {
		t.Errorf("SetProtected(false) on an unprotected descriptor changed=%v", changed)
	}
}

// Every ACE this package did not write must survive byte for byte. Rebuilding
// an ACL it does not understand is how a round trip silently drops a
// delegation.
func TestForeignACEsSurviveUntouched(t *testing.T) {
	a := allowACE(0x000F01FF, someSID)
	b := allowACE(0x00020014, everyone)
	sd := buildSD(t, [][]byte{a, b})

	out, _, err := SetProtected(sd, true)
	if err != nil {
		t.Fatalf("SetProtected: %v", err)
	}
	p, err := parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	list, err := aces(p.dacl)
	if err != nil {
		t.Fatalf("aces: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("got %d ACEs, want 3", len(list))
	}
	// The Deny must lead: a DACL is evaluated in order, so a Deny behind an
	// Allow that grants delete is never reached.
	if list[0][0] != aceTypeAccessDenied {
		t.Errorf("first ACE type = %#x, want the Deny", list[0][0])
	}
	for i, want := range [][]byte{a, b} {
		got := list[i+1]
		if string(got) != string(want) {
			t.Errorf("foreign ACE %d was altered:\n got % x\nwant % x", i, got, want)
		}
	}
}

// A protected object read back must report protected even when the Deny is not
// the only entry, and removal must leave the rest alone.
func TestRemoveProtectionKeepsOtherACEs(t *testing.T) {
	sd := buildSD(t, [][]byte{allowACE(0x000F01FF, someSID)})
	on, _, _ := SetProtected(sd, true)
	off, _, err := SetProtected(on, false)
	if err != nil {
		t.Fatalf("SetProtected(false): %v", err)
	}
	p, _ := parse(off)
	list, _ := aces(p.dacl)
	if len(list) != 1 {
		t.Fatalf("got %d ACEs after unprotect, want 1", len(list))
	}
}

func TestRejectsMalformed(t *testing.T) {
	if _, err := IsProtected([]byte{1, 2, 3}); err == nil {
		t.Error("a short descriptor must be an error")
	}
	// Not self-relative: the offsets would be pointers, not offsets.
	bad := make([]byte, sdHeaderLen)
	bad[0] = 1
	if _, err := IsProtected(bad); err == nil {
		t.Error("a non-self-relative descriptor must be an error")
	}
}

// Owner, group and SACL must survive a DACL edit, since a write-back replaces
// the whole attribute.
func TestOtherPartsSurvive(t *testing.T) {
	p := &parsed{
		revision: 1,
		control:  controlSelfRel | controlDACLPresent,
		owner:    someSID,
		group:    everyone,
		dacl:     buildACL(2, nil),
	}
	out, _, err := SetProtected(p.serialize(), true)
	if err != nil {
		t.Fatalf("SetProtected: %v", err)
	}
	got, err := parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if string(got.owner) != string(someSID) {
		t.Errorf("owner lost: % x", got.owner)
	}
	if string(got.group) != string(everyone) {
		t.Errorf("group lost: % x", got.group)
	}
}
