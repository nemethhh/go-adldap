package secdesc

import (
	"encoding/binary"
	"fmt"
)

// ridDomainAdmins is the well-known RID appended to a domain SID to name the
// Domain Admins group.
const ridDomainAdmins = 512

// rightsFullControl is GENERIC_ALL as AD stores it in these two attributes:
// the specific mask, not the generic bit. AD normalises GENERIC_ALL to this
// value on write, so writing it directly means a read-back compares equal on
// the first pass instead of showing a diff until something else rewrites it.
const rightsFullControl uint32 = 0x000F01FF

// aceTypeAccessAllowed is ACCESS_ALLOWED_ACE_TYPE, MS-DTYP 2.4.4.2.
const aceTypeAccessAllowed = 0x00

// domainAdminsSID appends the Domain Admins RID to a domain SID.
//
// A SID is a revision byte, a sub-authority count, a six-byte identifier
// authority, then that many little-endian uint32 sub-authorities (MS-DTYP
// 2.4.2), so appending a RID means growing the count and the tail together.
func domainAdminsSID(domainSID []byte) ([]byte, error) {
	n, err := sidLen(domainSID)
	if err != nil {
		return nil, err
	}
	if n != len(domainSID) {
		return nil, fmt.Errorf("secdesc: domain SID is %d bytes but declares %d", len(domainSID), n)
	}
	if domainSID[1] >= 15 {
		return nil, fmt.Errorf("secdesc: domain SID already has %d sub-authorities", domainSID[1])
	}
	out := make([]byte, 0, len(domainSID)+4)
	out = append(out, domainSID...)
	out[1]++
	out = binary.LittleEndian.AppendUint32(out, ridDomainAdmins)
	return out, nil
}

// allowFullACE is one ACCESS_ALLOWED ACE granting full control to trustee.
func allowFullACE(trustee []byte) []byte {
	size := aceHeaderLen + 4 + len(trustee)
	ace := make([]byte, 0, size)
	ace = append(ace, aceTypeAccessAllowed, 0x00) // type, no flags: this object only
	ace = binary.LittleEndian.AppendUint16(ace, uint16(size))
	ace = binary.LittleEndian.AppendUint32(ace, rightsFullControl)
	ace = append(ace, trustee...)
	return ace
}

// BuildPrincipalSD builds the descriptor that msDS-GroupMSAMembership and
// msDS-AllowedToActOnBehalfOfOtherIdentity both hold: owner and group are
// Domain Admins, and the DACL grants full control to each principal.
//
// An empty list produces a present but empty DACL, which denies everyone.
// That is deliberate and is not the same as omitting the DACL, which grants
// everyone full control — the difference between "nobody may retrieve this
// gMSA's password" and "anybody may".
func BuildPrincipalSD(domainSID []byte, principalSIDs [][]byte) ([]byte, error) {
	admins, err := domainAdminsSID(domainSID)
	if err != nil {
		return nil, err
	}
	list := make([][]byte, 0, len(principalSIDs))
	for _, sid := range principalSIDs {
		n, err := sidLen(sid)
		if err != nil {
			return nil, err
		}
		if n != len(sid) {
			return nil, fmt.Errorf("secdesc: principal SID is %d bytes but declares %d", len(sid), n)
		}
		list = append(list, allowFullACE(sid))
	}
	// Revision 2 is correct here: these ACEs carry no object GUID, so the
	// revision-4 requirement that object ACEs impose does not apply.
	dacl := buildACL(2, list)

	p := &parsed{
		revision: 1,
		control:  controlDACLPresent | controlSelfRel,
		owner:    admins,
		group:    admins,
		dacl:     dacl,
	}
	return p.serialize(), nil
}

// PrincipalSIDs reads back the trustees BuildPrincipalSD wrote.
//
// It returns SIDs rather than object GUIDs because turning one into the other
// is a directory search, and this package performs no I/O. An absent or empty
// attribute is an empty list, not an error: an account with no principals is
// an ordinary state.
func PrincipalSIDs(sd []byte) ([][]byte, error) {
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
	var out [][]byte
	for _, ace := range list {
		// Only plain allow ACEs name a principal here. Anything else in this
		// attribute was not written by us and is not a principal, so skipping
		// it is the honest reading rather than a guess.
		if len(ace) < aceHeaderLen+4 || ace[0] != aceTypeAccessAllowed {
			continue
		}
		sid := ace[aceHeaderLen+4:]
		n, err := sidLen(sid)
		if err != nil || n > len(sid) {
			return nil, fmt.Errorf("secdesc: malformed trustee SID in principal descriptor")
		}
		out = append(out, sid[:n])
	}
	return out, nil
}
