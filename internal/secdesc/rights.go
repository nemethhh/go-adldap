package secdesc

import (
	"fmt"
	"strings"

	"github.com/nemethhh/go-adcore"
)

// The ADS_RIGHTS_ENUM values, named as System.DirectoryServices.
// ActiveDirectoryRights spells them. These names are the contract the
// provider's access_rule resource already exposes and go-adpwsh already
// emits; a different spelling here is a silent behaviour split between the
// two backends, not a compile error.
const (
	rightCreateChild   uint32 = 0x00000001
	rightDeleteChild   uint32 = 0x00000002
	rightListChildren  uint32 = 0x00000004
	rightSelf          uint32 = 0x00000008
	rightReadProperty  uint32 = 0x00000010
	rightWriteProperty uint32 = 0x00000020
	// rightDeleteTree and rightDelete are already declared in secdesc.go for
	// the protection ACE; they are not redeclared here.
	rightListObject           uint32 = 0x00000080
	rightReadControl          uint32 = 0x00020000
	rightWriteDacl            uint32 = 0x00040000
	rightWriteOwner           uint32 = 0x00080000
	rightGenericAll           uint32 = 0x000F01FF
	rightGenericExecute       uint32 = 0x00020004
	rightGenericWrite         uint32 = 0x00020028
	rightGenericRead          uint32 = 0x00020094
	rightSynchronize          uint32 = 0x00100000
	rightAccessSystemSecurity uint32 = 0x01000000
)

// rightsTable is ordered by bit value so RightsNames produces a stable list.
// GenericAll is deliberately absent: it is a composite handled separately,
// and including it here would match on every one of its constituent bits.
var rightsTable = []struct {
	bit  uint32
	name adcore.Right
}{
	{rightCreateChild, "CreateChild"},
	{rightDeleteChild, "DeleteChild"},
	{rightListChildren, "ListChildren"},
	{rightSelf, "Self"},
	{rightReadProperty, "ReadProperty"},
	{rightWriteProperty, "WriteProperty"},
	{rightDeleteTree, "DeleteTree"},
	{rightListObject, "ListObject"},
	{RightControlAccess, "ExtendedRight"},
	{rightDelete, "Delete"},
	{rightReadControl, "ReadControl"},
	{rightWriteDacl, "WriteDacl"},
	{rightWriteOwner, "WriteOwner"},
	{rightSynchronize, "Synchronize"},
	{rightAccessSystemSecurity, "AccessSystemSecurity"},
}

// composites are the names that set more than one bit. They are resolved on
// the way in and, for GenericAll alone, on the way out.
var composites = map[string]uint32{
	"genericall":     rightGenericAll,
	"genericexecute": rightGenericExecute,
	"genericwrite":   rightGenericWrite,
	"genericread":    rightGenericRead,
}

// RightsMask folds right names into the access mask an ACE carries.
//
// An unrecognised name is an error naming it. Dropping it would grant less
// than the caller asked for and report success, which in an access-control
// system is the worst of the available outcomes: the apply is green and the
// permission is missing.
func RightsMask(names []adcore.Right) (uint32, error) {
	var mask uint32
	for _, n := range names {
		key := strings.ToLower(strings.TrimSpace(string(n)))
		if v, ok := composites[key]; ok {
			mask |= v
			continue
		}
		found := false
		for _, r := range rightsTable {
			if strings.ToLower(string(r.name)) == key {
				mask |= r.bit
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("secdesc: unknown access right %q", string(n))
		}
	}
	return mask, nil
}

// RightsNames is the inverse, in bit order so two reads of one ACE always
// produce the same list and Terraform sees no diff.
//
// A mask carrying every GenericAll bit is emitted as GenericAll alone: that
// is what AD's own tooling shows and what go-adpwsh emits, and expanding it
// into nine names would be a permanent diff for anyone switching backends.
func RightsNames(mask uint32) []adcore.Right {
	if mask&rightGenericAll == rightGenericAll {
		return []adcore.Right{"GenericAll"}
	}
	var out []adcore.Right
	for _, r := range rightsTable {
		if mask&r.bit == r.bit && r.bit != 0 {
			out = append(out, r.name)
		}
	}
	return out
}
