package secdesc

import (
	"encoding/binary"
	"errors"

	"github.com/nemethhh/go-adcore"
)

// ACE type codes, MS-DTYP 2.4.4. aceTypeAccessAllowed, aceTypeAccessDenied and
// aceTypeDeniedObject are declared in principals.go and secdesc.go.
const aceTypeAllowedObject = 0x05

// AceFlags bits, MS-DTYP 2.4.4.1.
const (
	AceFlagContainerInherit = 0x02
	AceFlagNoPropagate      = 0x04
	AceFlagInheritOnly      = 0x08
	AceFlagInherited        = 0x10
)

// DecodedACE is one explicit entry, still in binary terms: SIDs and GUIDs are
// raw bytes, because turning either into a string is a formatting decision
// this package does not make and turning a SID into a principal is a
// directory read it cannot perform.
type DecodedACE struct {
	TrusteeSID          []byte
	Deny                bool
	Mask                uint32
	ObjectType          []byte
	InheritedObjectType []byte
	Flags               byte
	Inherited           bool
}

// DecodeACEs reads every ACE this package understands out of a descriptor's
// DACL.
//
// An ACE type it does not model — callback, conditional, or anything
// Microsoft adds later — is skipped, not guessed at and not fatal. Those
// entries are still preserved byte for byte on a write, because EncodeACEs's
// caller copies them; refusing to read an object because one is present would
// make every object carrying one unmanageable.
func DecodeACEs(sd []byte) ([]DecodedACE, error) {
	if len(sd) == 0 {
		return nil, nil
	}
	p, err := parse(sd)
	if err != nil {
		return nil, err
	}
	if len(p.dacl) == 0 {
		return nil, nil
	}
	list, err := aces(p.dacl)
	if err != nil {
		return nil, err
	}
	out := make([]DecodedACE, 0, len(list))
	for _, ace := range list {
		d, ok, err := decodeACE(ace)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// decodeACE returns ok=false for an ACE type this package does not model.
func decodeACE(ace []byte) (DecodedACE, bool, error) {
	if len(ace) < aceHeaderLen+4 {
		return DecodedACE{}, false, errors.New("secdesc: ACE shorter than its header")
	}
	var (
		d      DecodedACE
		object bool
	)
	switch ace[0] {
	case aceTypeAccessAllowed:
	case aceTypeAccessDenied:
		d.Deny = true
	case aceTypeAllowedObject:
		object = true
	case aceTypeDeniedObject:
		d.Deny, object = true, true
	default:
		return DecodedACE{}, false, nil
	}

	d.Flags = ace[1]
	d.Inherited = d.Flags&AceFlagInherited != 0

	off := aceHeaderLen
	d.Mask = binary.LittleEndian.Uint32(ace[off : off+4])
	off += 4

	if object {
		if len(ace) < off+4 {
			return DecodedACE{}, false, errors.New("secdesc: object ACE has no flags word")
		}
		objFlags := binary.LittleEndian.Uint32(ace[off : off+4])
		off += 4
		// The GUIDs present, and therefore where the SID starts, are what the
		// flags word says. Reading the SID at a fixed offset yields a
		// well-formed SID naming the wrong principal.
		if objFlags&aceObjectTypePresent != 0 {
			if len(ace) < off+16 {
				return DecodedACE{}, false, errors.New("secdesc: object ACE truncated before its object type")
			}
			d.ObjectType = ace[off : off+16]
			off += 16
		}
		if objFlags&aceInheritedObjectTypePresent != 0 {
			if len(ace) < off+16 {
				return DecodedACE{}, false, errors.New("secdesc: object ACE truncated before its inherited object type")
			}
			d.InheritedObjectType = ace[off : off+16]
			off += 16
		}
	}

	sid := ace[off:]
	n, err := sidLen(sid)
	if err != nil {
		return DecodedACE{}, false, err
	}
	if n > len(sid) {
		return DecodedACE{}, false, errors.New("secdesc: ACE trustee SID truncated")
	}
	d.TrusteeSID = sid[:n]
	return d, true, nil
}

// InheritanceOf maps an ACE's flags to the three-valued vocabulary adcore
// uses. It is deliberately the same collapse go-adpwsh performs through
// PowerShell's ActiveDirectorySecurityInheritance: "this object and all
// descendants" and "all descendants" both read as descendants, and "this
// object and immediate children" and "immediate children" both read as
// children. The mapping is lossy, identically on both backends, which is the
// property that keeps a user switching between them from seeing a diff.
func InheritanceOf(flags byte) adcore.Inheritance {
	if flags&AceFlagContainerInherit == 0 {
		return adcore.InheritanceThis
	}
	if flags&AceFlagNoPropagate != 0 {
		return adcore.InheritanceChildren
	}
	return adcore.InheritanceDescendants
}

// FlagsFor is the inverse. InheritanceThis carries no inheritance bits at all;
// the other two set INHERIT_ONLY, matching the Descendents and Children forms
// New-AdAceFromSpec writes, so an ACE written here and read by the PowerShell
// backend round-trips.
func FlagsFor(inh adcore.Inheritance) byte {
	switch inh {
	case adcore.InheritanceDescendants:
		return AceFlagContainerInherit | AceFlagInheritOnly
	case adcore.InheritanceChildren:
		return AceFlagContainerInherit | AceFlagNoPropagate | AceFlagInheritOnly
	default:
		return 0
	}
}

// EncodeACE renders one entry. The type is chosen by whether a GUID is
// present, because AD requires the object form for an entry carrying one and
// refuses an object ACE that carries neither.
func EncodeACE(a DecodedACE) []byte {
	object := len(a.ObjectType) == 16 || len(a.InheritedObjectType) == 16

	var t byte
	switch {
	case object && a.Deny:
		t = aceTypeDeniedObject
	case object:
		t = aceTypeAllowedObject
	case a.Deny:
		t = aceTypeAccessDenied
	default:
		t = aceTypeAccessAllowed
	}

	body := binary.LittleEndian.AppendUint32(nil, a.Mask)
	if object {
		var objFlags uint32
		if len(a.ObjectType) == 16 {
			objFlags |= aceObjectTypePresent
		}
		if len(a.InheritedObjectType) == 16 {
			objFlags |= aceInheritedObjectTypePresent
		}
		body = binary.LittleEndian.AppendUint32(body, objFlags)
		if len(a.ObjectType) == 16 {
			body = append(body, a.ObjectType...)
		}
		if len(a.InheritedObjectType) == 16 {
			body = append(body, a.InheritedObjectType...)
		}
	}
	body = append(body, a.TrusteeSID...)

	size := aceHeaderLen + len(body)
	out := []byte{t, a.Flags}
	out = binary.LittleEndian.AppendUint16(out, uint16(size))
	return append(out, body...)
}

// aclRevisionFor is 4 once any entry is an object ACE. A DACL left at
// revision 2 with an object ACE in it is a descriptor the directory rejects,
// and the refusal names the attribute rather than the revision.
func aclRevisionFor(list [][]byte) byte {
	for _, ace := range list {
		if ace[0] == aceTypeAllowedObject || ace[0] == aceTypeDeniedObject {
			return aclRevisionDS
		}
	}
	return 2
}

// AddACEs appends entries to a descriptor's DACL, leaving every existing
// entry — modelled or not — exactly where it was.
//
// It reports changed=false for an empty add, so the caller can skip a write
// that would generate replication for nothing.
func AddACEs(sd []byte, add []DecodedACE) ([]byte, bool, error) {
	if len(add) == 0 {
		return sd, false, nil
	}
	p, err := parse(sd)
	if err != nil {
		return nil, false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return nil, false, err
	}
	for _, a := range add {
		list = append(list, EncodeACE(a))
	}
	p.dacl = buildACL(aclRevisionFor(list), list)
	p.control |= controlDACLPresent
	return p.serialize(), true, nil
}

// RemoveACEs drops every entry that decodes, is not inherited, and matches.
//
// An inherited entry is never a candidate: it is a system-stamped copy of a
// parent's ACE, removing it locally means nothing, and AD puts it back. An
// entry this package cannot decode is never a candidate either, because match
// was never shown it.
func RemoveACEs(sd []byte, match func(DecodedACE) bool) ([]byte, bool, error) {
	p, err := parse(sd)
	if err != nil {
		return nil, false, err
	}
	list, err := aces(p.dacl)
	if err != nil {
		return nil, false, err
	}
	kept := make([][]byte, 0, len(list))
	changed := false
	for _, ace := range list {
		d, ok, err := decodeACE(ace)
		if err != nil {
			return nil, false, err
		}
		if ok && !d.Inherited && match(d) {
			changed = true
			continue
		}
		kept = append(kept, ace)
	}
	if !changed {
		return sd, false, nil
	}
	p.dacl = buildACL(aclRevisionFor(kept), kept)
	p.control |= controlDACLPresent
	return p.serialize(), true, nil
}
