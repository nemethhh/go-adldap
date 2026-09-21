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
