// Package secdesc edits the one part of an Active Directory security
// descriptor this backend needs: the Deny ACE that implements
// ProtectedFromAccidentalDeletion.
//
// It deliberately does not model an ACL. Every ACE carries its own size in a
// uniform four-byte header, so existing entries can be walked and copied as
// opaque bytes without understanding any of them — which is what keeps an
// object ACE, a callback ACE or anything Microsoft adds later from being
// corrupted by a round trip through here. Only the descriptor's own header,
// the ACL header and the single ACE type this package writes are interpreted.
//
// Layouts are MS-DTYP: 2.4.6 (SECURITY_DESCRIPTOR), 2.4.5 (ACL), 2.4.4 (ACE),
// 2.4.2 (SID). Everything is little-endian except a SID's identifier
// authority.
package secdesc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	sdHeaderLen  = 20
	aclHeaderLen = 8
	aceHeaderLen = 4

	controlDACLPresent = 0x0004
	controlSelfRel     = 0x8000

	aceTypeAccessDenied = 0x01

	// DELETE and ADS_RIGHT_DS_DELETE_TREE. AD's own protection denies both in
	// one ACE; denying only DELETE leaves the object removable with a subtree
	// delete.
	rightDelete     = 0x00010000
	rightDeleteTree = 0x00000040

	protectionMask = rightDelete | rightDeleteTree
)

// everyone is S-1-1-0, the trustee AD's own protection denies.
var everyone = []byte{1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}

type parsed struct {
	revision byte
	sbz1     byte
	control  uint16
	owner    []byte
	group    []byte
	sacl     []byte
	dacl     []byte
}

// sidLen reads a SID's length from its sub-authority count.
func sidLen(b []byte) (int, error) {
	if len(b) < 8 {
		return 0, errors.New("secdesc: SID truncated")
	}
	n := 8 + 4*int(b[1])
	if len(b) < n {
		return 0, errors.New("secdesc: SID shorter than its sub-authority count")
	}
	return n, nil
}

func aclLen(b []byte) (int, error) {
	if len(b) < aclHeaderLen {
		return 0, errors.New("secdesc: ACL truncated")
	}
	n := int(binary.LittleEndian.Uint16(b[2:4]))
	if n < aclHeaderLen || len(b) < n {
		return 0, errors.New("secdesc: ACL shorter than its stated size")
	}
	return n, nil
}

func parse(sd []byte) (*parsed, error) {
	if len(sd) < sdHeaderLen {
		return nil, fmt.Errorf("secdesc: descriptor is %d bytes, too short", len(sd))
	}
	p := &parsed{
		revision: sd[0],
		sbz1:     sd[1],
		control:  binary.LittleEndian.Uint16(sd[2:4]),
	}
	if p.control&controlSelfRel == 0 {
		return nil, errors.New("secdesc: descriptor is not self-relative")
	}

	slice := func(off uint32, length func([]byte) (int, error)) ([]byte, error) {
		if off == 0 {
			return nil, nil
		}
		if int(off) >= len(sd) {
			return nil, errors.New("secdesc: offset past the end of the descriptor")
		}
		n, err := length(sd[off:])
		if err != nil {
			return nil, err
		}
		return sd[off : int(off)+n], nil
	}

	var err error
	if p.owner, err = slice(binary.LittleEndian.Uint32(sd[4:8]), sidLen); err != nil {
		return nil, err
	}
	if p.group, err = slice(binary.LittleEndian.Uint32(sd[8:12]), sidLen); err != nil {
		return nil, err
	}
	if p.sacl, err = slice(binary.LittleEndian.Uint32(sd[12:16]), aclLen); err != nil {
		return nil, err
	}
	if p.dacl, err = slice(binary.LittleEndian.Uint32(sd[16:20]), aclLen); err != nil {
		return nil, err
	}
	return p, nil
}

// serialize reassembles a self-relative descriptor. The parts may be emitted
// in any order provided the offsets agree; ACLs first matches what Windows
// produces.
func (p *parsed) serialize() []byte {
	out := make([]byte, sdHeaderLen)
	out[0] = p.revision
	out[1] = p.sbz1
	binary.LittleEndian.PutUint16(out[2:4], p.control)

	put := func(part []byte, at int) {
		if len(part) == 0 {
			binary.LittleEndian.PutUint32(out[at:at+4], 0)
			return
		}
		binary.LittleEndian.PutUint32(out[at:at+4], uint32(len(out)))
		out = append(out, part...)
	}
	put(p.sacl, 12)
	put(p.dacl, 16)
	put(p.owner, 4)
	put(p.group, 8)
	return out
}

// aces splits an ACL body into its entries, each still opaque.
func aces(acl []byte) ([][]byte, error) {
	if len(acl) == 0 {
		return nil, nil
	}
	count := int(binary.LittleEndian.Uint16(acl[4:6]))
	out := make([][]byte, 0, count)
	off := aclHeaderLen
	for i := 0; i < count; i++ {
		if off+aceHeaderLen > len(acl) {
			return nil, errors.New("secdesc: ACE count exceeds the ACL body")
		}
		n := int(binary.LittleEndian.Uint16(acl[off+2 : off+4]))
		if n < aceHeaderLen || off+n > len(acl) {
			return nil, errors.New("secdesc: ACE shorter than its stated size")
		}
		out = append(out, acl[off:off+n])
		off += n
	}
	return out, nil
}

// buildACL reassembles an ACL around a new ACE list.
func buildACL(revision byte, list [][]byte) []byte {
	size := aclHeaderLen
	for _, a := range list {
		size += len(a)
	}
	out := make([]byte, aclHeaderLen, size)
	out[0] = revision
	binary.LittleEndian.PutUint16(out[2:4], uint16(size))
	binary.LittleEndian.PutUint16(out[4:6], uint16(len(list)))
	for _, a := range list {
		out = append(out, a...)
	}
	return out
}

// isProtectionACE reports whether an ACE is one this package wrote: a plain
// Deny for Everyone carrying either delete right.
func isProtectionACE(ace []byte) bool {
	if len(ace) < aceHeaderLen+4+len(everyone) {
		return false
	}
	if ace[0] != aceTypeAccessDenied {
		return false
	}
	mask := binary.LittleEndian.Uint32(ace[4:8])
	if mask&protectionMask == 0 {
		return false
	}
	sid := ace[8:]
	if len(sid) < len(everyone) {
		return false
	}
	for i := range everyone {
		if sid[i] != everyone[i] {
			return false
		}
	}
	return true
}

func protectionACE() []byte {
	ace := make([]byte, aceHeaderLen+4+len(everyone))
	ace[0] = aceTypeAccessDenied
	ace[1] = 0 // this object only; protection is not inherited
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], protectionMask)
	copy(ace[8:], everyone)
	return ace
}

// IsProtected reports whether the descriptor denies Everyone the delete
// rights.
func IsProtected(sd []byte) (bool, error) {
	p, err := parse(sd)
	if err != nil {
		return false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return false, err
	}
	for _, a := range list {
		if isProtectionACE(a) {
			return true, nil
		}
	}
	return false, nil
}

// SetProtected returns the descriptor with the protection ACE added or
// removed. It is idempotent, and returns ok=false when nothing changed, so a
// caller can skip a pointless write.
//
// The ACE goes at the front: a DACL is evaluated in order, so a Deny placed
// after an Allow that grants delete would never be reached.
func SetProtected(sd []byte, on bool) (out []byte, ok bool, err error) {
	p, err := parse(sd)
	if err != nil {
		return nil, false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return nil, false, err
	}

	kept := make([][]byte, 0, len(list)+1)
	found := false
	for _, a := range list {
		if isProtectionACE(a) {
			found = true
			continue
		}
		kept = append(kept, a)
	}
	if on == found {
		return sd, false, nil
	}
	if on {
		kept = append([][]byte{protectionACE()}, kept...)
	}

	revision := byte(2) // ACL_REVISION
	if len(p.dacl) > 0 {
		revision = p.dacl[0]
	}
	p.dacl = buildACL(revision, kept)
	p.control |= controlDACLPresent
	return p.serialize(), true, nil
}

// --- object ACEs -----------------------------------------------------------
//
// An extended right is denied with an ACCESS_DENIED_OBJECT_ACE, which carries
// the right's schema GUID after the mask:
//
//	AceType(1) AceFlags(1) AceSize(2) Mask(4) Flags(4)
//	[ObjectType(16)] [InheritedObjectType(16)] Sid(...)
//
// The two GUIDs are present only when their bit is set in Flags, so the SID's
// offset is not fixed — which is why this is parsed rather than indexed.

const (
	aceTypeDeniedObject = 0x06

	aceObjectTypePresent          = 0x00000001
	aceInheritedObjectTypePresent = 0x00000002

	// RightControlAccess is ADS_RIGHT_DS_CONTROL_ACCESS, the mask an extended
	// right is granted or denied with.
	RightControlAccess = 0x00000100

	// aclRevisionDS is required once a DACL contains an object ACE. Leaving an
	// ACL at revision 2 with an object ACE in it produces a descriptor the
	// directory rejects.
	aclRevisionDS = 4
)

// SIDEveryone is S-1-1-0 and SIDSelf is S-1-5-10, the two trustees AD denies
// when an account may not change its own password.
var (
	SIDEveryone = everyone
	SIDSelf     = []byte{1, 1, 0, 0, 0, 0, 0, 5, 10, 0, 0, 0}
)

// deniedObject reports whether an ACE denies mask on objectType to trustee.
func deniedObject(ace []byte, mask uint32, objectType, trustee []byte) bool {
	if len(ace) < aceHeaderLen+8 || ace[0] != aceTypeDeniedObject {
		return false
	}
	if binary.LittleEndian.Uint32(ace[4:8])&mask == 0 {
		return false
	}
	flags := binary.LittleEndian.Uint32(ace[8:12])
	off := 12
	if flags&aceObjectTypePresent != 0 {
		if len(ace) < off+16 {
			return false
		}
		if string(ace[off:off+16]) != string(objectType) {
			return false
		}
		off += 16
	} else {
		// No object type means the ACE covers every extended right, which
		// includes this one.
		if len(objectType) > 0 {
			return false
		}
	}
	if flags&aceInheritedObjectTypePresent != 0 {
		off += 16
	}
	return len(ace) >= off+len(trustee) && string(ace[off:off+len(trustee)]) == string(trustee)
}

func deniedObjectACE(mask uint32, objectType, trustee []byte) []byte {
	ace := make([]byte, aceHeaderLen+4+4+len(objectType)+len(trustee))
	ace[0] = aceTypeDeniedObject
	ace[1] = 0 // this object only
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:], objectType)
	copy(ace[12+len(objectType):], trustee)
	return ace
}

// HasDeniedObjectRight reports whether any of the trustees is denied mask on
// objectType.
//
// Any, not all: if Everyone is denied the right then the account cannot use it
// whatever the other entries say, so treating that as "still allowed" would
// report a state the directory does not have.
func HasDeniedObjectRight(sd []byte, mask uint32, objectType []byte, trustees ...[]byte) (bool, error) {
	p, err := parse(sd)
	if err != nil {
		return false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return false, err
	}
	for _, a := range list {
		for _, t := range trustees {
			if deniedObject(a, mask, objectType, t) {
				return true, nil
			}
		}
	}
	return false, nil
}

// SetDeniedObjectRight adds or removes a Deny of mask on objectType for each
// trustee. It is idempotent and reports whether anything changed.
func SetDeniedObjectRight(sd []byte, on bool, mask uint32, objectType []byte, trustees ...[]byte) (out []byte, ok bool, err error) {
	p, err := parse(sd)
	if err != nil {
		return nil, false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return nil, false, err
	}

	kept := make([][]byte, 0, len(list)+len(trustees))
	removed := 0
	for _, a := range list {
		match := false
		for _, t := range trustees {
			if deniedObject(a, mask, objectType, t) {
				match = true
				break
			}
		}
		if match {
			removed++
			continue
		}
		kept = append(kept, a)
	}

	if !on {
		if removed == 0 {
			return sd, false, nil
		}
	} else {
		if removed == len(trustees) && removed > 0 {
			return sd, false, nil // already exactly what was asked for
		}
		// Deny entries lead: a DACL is evaluated in order.
		add := make([][]byte, 0, len(trustees))
		for _, t := range trustees {
			add = append(add, deniedObjectACE(mask, objectType, t))
		}
		kept = append(add, kept...)
	}

	revision := byte(aclRevisionDS)
	if len(p.dacl) > 0 && p.dacl[0] > aclRevisionDS {
		revision = p.dacl[0]
	}
	p.dacl = buildACL(revision, kept)
	p.control |= controlDACLPresent
	return p.serialize(), true, nil
}
