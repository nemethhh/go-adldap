package secdesc

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTestSD assembles a self-relative descriptor around a raw ACE list, so
// the decoder is tested against bytes rather than against its own encoder.
func buildTestSD(t *testing.T, list [][]byte) []byte {
	t.Helper()
	p := &parsed{
		revision: 1,
		control:  controlDACLPresent | controlSelfRel,
		owner:    domainSID,
		group:    domainSID,
		dacl:     buildACL(4, list),
	}
	return p.serialize()
}

func rawAllowACE(flags byte, mask uint32, sid []byte) []byte {
	size := aceHeaderLen + 4 + len(sid)
	ace := []byte{0x00, flags}
	ace = binary.LittleEndian.AppendUint16(ace, uint16(size))
	ace = binary.LittleEndian.AppendUint32(ace, mask)
	return append(ace, sid...)
}

func rawAllowObjectACE(flags byte, mask, objFlags uint32, objectType, inheritedType, sid []byte) []byte {
	body := binary.LittleEndian.AppendUint32(nil, mask)
	body = binary.LittleEndian.AppendUint32(body, objFlags)
	if objFlags&aceObjectTypePresent != 0 {
		body = append(body, objectType...)
	}
	if objFlags&aceInheritedObjectTypePresent != 0 {
		body = append(body, inheritedType...)
	}
	body = append(body, sid...)
	size := aceHeaderLen + len(body)
	ace := []byte{0x05, flags} // ACCESS_ALLOWED_OBJECT_ACE_TYPE
	ace = binary.LittleEndian.AppendUint16(ace, uint16(size))
	return append(ace, body...)
}

var testGUID = []byte{
	0x53, 0x1a, 0x72, 0xab, 0x2f, 0x1e, 0xd0, 0x11,
	0x98, 0x19, 0x00, 0xaa, 0x00, 0x40, 0x52, 0x9b,
}

var testGUID2 = []byte{
	0xbf, 0x96, 0x7a, 0xba, 0x0d, 0xe6, 0x11, 0xd0,
	0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2,
}

func TestDecodeACEsPlainAllow(t *testing.T) {
	trustee := sidWithRID(domainSID, 1104)
	sd := buildTestSD(t, [][]byte{rawAllowACE(0x00, 0x00000010, trustee)})

	got, err := DecodeACEs(sd)
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ACEs, want 1", len(got))
	}
	a := got[0]
	if a.Deny {
		t.Error("Deny = true, want false")
	}
	if a.Mask != 0x00000010 {
		t.Errorf("Mask = %#x", a.Mask)
	}
	if !bytes.Equal(a.TrusteeSID, trustee) {
		t.Error("trustee SID did not decode")
	}
	if a.ObjectType != nil || a.InheritedObjectType != nil {
		t.Error("a plain ACE decoded object GUIDs it does not carry")
	}
}

// The SID's offset in an object ACE depends on which GUIDs the flags word says
// are present. Reading it at a fixed offset produces a plausible SID that
// names the wrong principal, which is the failure this case exists to catch.
func TestDecodeACEsObjectACEWithOnlyTheInheritedGUID(t *testing.T) {
	trustee := sidWithRID(domainSID, 1105)
	sd := buildTestSD(t, [][]byte{
		rawAllowObjectACE(0x02|0x08, 0x00000100, aceInheritedObjectTypePresent, nil, testGUID2, trustee),
	})

	got, err := DecodeACEs(sd)
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	a := got[0]
	if a.ObjectType != nil {
		t.Errorf("ObjectType = %x, want nil", a.ObjectType)
	}
	if !bytes.Equal(a.InheritedObjectType, testGUID2) {
		t.Errorf("InheritedObjectType = %x, want %x", a.InheritedObjectType, testGUID2)
	}
	if !bytes.Equal(a.TrusteeSID, trustee) {
		t.Errorf("TrusteeSID = %x, want %x — the SID offset must follow the flags word", a.TrusteeSID, trustee)
	}
}

func TestDecodeACEsObjectACEWithBothGUIDs(t *testing.T) {
	trustee := sidWithRID(domainSID, 1106)
	sd := buildTestSD(t, [][]byte{
		rawAllowObjectACE(0x02, 0x00000030,
			aceObjectTypePresent|aceInheritedObjectTypePresent, testGUID, testGUID2, trustee),
	})

	got, err := DecodeACEs(sd)
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	a := got[0]
	if !bytes.Equal(a.ObjectType, testGUID) {
		t.Errorf("ObjectType = %x, want %x", a.ObjectType, testGUID)
	}
	if !bytes.Equal(a.InheritedObjectType, testGUID2) {
		t.Errorf("InheritedObjectType = %x, want %x", a.InheritedObjectType, testGUID2)
	}
	if !bytes.Equal(a.TrusteeSID, trustee) {
		t.Error("trustee SID did not decode")
	}
}

func TestDecodeACEsMarksInherited(t *testing.T) {
	const inheritedFlag = 0x10
	trustee := sidWithRID(domainSID, 1107)
	sd := buildTestSD(t, [][]byte{rawAllowACE(inheritedFlag, 0x00000010, trustee)})

	got, err := DecodeACEs(sd)
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	if !got[0].Inherited {
		t.Error("Inherited = false; an inherited ACE must be marked, it is never managed")
	}
}

// An ACE type this package does not model is skipped rather than guessed at or
// fatal. A conditional or callback ACE in the DACL is not ours to interpret,
// and refusing to read the object because one is present would make every
// object carrying one unmanageable.
func TestDecodeACEsSkipsUnknownTypes(t *testing.T) {
	trustee := sidWithRID(domainSID, 1108)
	callback := rawAllowACE(0x00, 0x00000010, trustee)
	callback[0] = 0x09 // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
	plain := rawAllowACE(0x00, 0x00000020, trustee)

	got, err := DecodeACEs(buildTestSD(t, [][]byte{callback, plain}))
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d ACEs, want 1 (the callback ACE must be skipped)", len(got))
	}
	if got[0].Mask != 0x00000020 {
		t.Errorf("the wrong ACE survived: mask %#x", got[0].Mask)
	}
}

func TestDecodeACEsEmptyDescriptor(t *testing.T) {
	got, err := DecodeACEs(nil)
	if err != nil {
		t.Fatalf("DecodeACEs(nil): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d ACEs, want 0", len(got))
	}
}

func TestEncodeACERoundTripsThroughDecode(t *testing.T) {
	trustee := sidWithRID(domainSID, 1200)
	in := []DecodedACE{
		{TrusteeSID: trustee, Mask: 0x00000010},
		{TrusteeSID: trustee, Deny: true, Mask: 0x00000020, Flags: AceFlagContainerInherit | AceFlagInheritOnly},
		{TrusteeSID: trustee, Mask: RightControlAccess, ObjectType: testGUID,
			Flags: AceFlagContainerInherit | AceFlagInheritOnly},
		{TrusteeSID: trustee, Mask: 0x00000030, ObjectType: testGUID, InheritedObjectType: testGUID2},
	}
	for i, want := range in {
		got, ok, err := decodeACE(EncodeACE(want))
		if err != nil {
			t.Fatalf("case %d: decode: %v", i, err)
		}
		if !ok {
			t.Fatalf("case %d: the encoded ACE did not decode", i)
		}
		if got.Deny != want.Deny || got.Mask != want.Mask || got.Flags != want.Flags {
			t.Errorf("case %d: got %+v, want %+v", i, got, want)
		}
		if !bytes.Equal(got.TrusteeSID, want.TrusteeSID) {
			t.Errorf("case %d: trustee did not round trip", i)
		}
		if !bytes.Equal(got.ObjectType, want.ObjectType) {
			t.Errorf("case %d: ObjectType %x, want %x", i, got.ObjectType, want.ObjectType)
		}
		if !bytes.Equal(got.InheritedObjectType, want.InheritedObjectType) {
			t.Errorf("case %d: InheritedObjectType %x, want %x", i, got.InheritedObjectType, want.InheritedObjectType)
		}
	}
}

func TestAddACEsKeepsWhatIsThere(t *testing.T) {
	existing := sidWithRID(domainSID, 1300)
	added := sidWithRID(domainSID, 1301)
	callback := rawAllowACE(0x00, 0x00000010, existing)
	callback[0] = 0x09 // an ACE type this package does not model

	sd := buildTestSD(t, [][]byte{rawAllowACE(0x00, 0x00000010, existing), callback})

	out, changed, err := AddACEs(sd, []DecodedACE{{TrusteeSID: added, Mask: 0x00000020}})
	if err != nil {
		t.Fatalf("AddACEs: %v", err)
	}
	if !changed {
		t.Fatal("changed = false after adding an ACE")
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
		t.Fatalf("the DACL holds %d ACEs, want 3 — the unmodelled one must survive", len(list))
	}
	if list[1][0] != 0x09 {
		t.Error("the callback ACE was not carried through byte for byte")
	}
}

// An object ACE forces the DACL to revision 4. At revision 2 the directory
// rejects the whole descriptor, with a message about the attribute rather
// than about the revision.
func TestAddACEsRaisesTheACLRevisionForAnObjectACE(t *testing.T) {
	sd := buildTestSD(t, nil)
	out, _, err := AddACEs(sd, []DecodedACE{
		{TrusteeSID: sidWithRID(domainSID, 1400), Mask: RightControlAccess, ObjectType: testGUID},
	})
	if err != nil {
		t.Fatalf("AddACEs: %v", err)
	}
	p, err := parse(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.dacl[0] != aclRevisionDS {
		t.Errorf("ACL revision = %d, want %d once an object ACE is present", p.dacl[0], aclRevisionDS)
	}
}

func TestRemoveACEsNeverTouchesAnInheritedOne(t *testing.T) {
	trustee := sidWithRID(domainSID, 1500)
	sd := buildTestSD(t, [][]byte{
		rawAllowACE(AceFlagInherited, 0x00000010, trustee),
		rawAllowACE(0x00, 0x00000010, trustee),
	})

	out, changed, err := RemoveACEs(sd, func(a DecodedACE) bool {
		return bytes.Equal(a.TrusteeSID, trustee) && a.Mask == 0x00000010
	})
	if err != nil {
		t.Fatalf("RemoveACEs: %v", err)
	}
	if !changed {
		t.Fatal("changed = false; the explicit ACE should have gone")
	}

	got, err := DecodeACEs(out)
	if err != nil {
		t.Fatalf("DecodeACEs: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d ACEs remain, want 1", len(got))
	}
	if !got[0].Inherited {
		t.Error("the surviving ACE is the explicit one; the inherited one was removed")
	}
}

func TestRemoveACEsReportsNoChangeWhenNothingMatches(t *testing.T) {
	sd := buildTestSD(t, [][]byte{rawAllowACE(0x00, 0x00000010, sidWithRID(domainSID, 1600))})
	out, changed, err := RemoveACEs(sd, func(DecodedACE) bool { return false })
	if err != nil {
		t.Fatalf("RemoveACEs: %v", err)
	}
	if changed {
		t.Error("changed = true with no matching ACE; the caller would write for nothing and replicate it")
	}
	if !bytes.Equal(out, sd) {
		t.Error("the descriptor was rewritten although nothing matched")
	}
}
