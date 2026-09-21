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
