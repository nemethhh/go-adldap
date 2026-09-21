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

// rightsTable is every ActiveDirectoryRights name with the mask it sets,
// ordered by value ASCENDING. Both composites and single bits are in it,
// because .NET's [Flags] formatting does not distinguish them: it matches the
// largest value it can and works down, which is what makes a mask holding all
// of GENERIC_READ's bits render as "GenericRead" rather than as its four
// constituents. Emitting the constituents is a permanent diff for anyone
// switching backends, and was found that way — see LAB.md, the differential
// suite.
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
	{rightGenericExecute, "GenericExecute"},
	{rightGenericWrite, "GenericWrite"},
	{rightGenericRead, "GenericRead"},
	{rightWriteDacl, "WriteDacl"},
	{rightWriteOwner, "WriteOwner"},
	{rightGenericAll, "GenericAll"},
	{rightSynchronize, "Synchronize"},
	{rightAccessSystemSecurity, "AccessSystemSecurity"},
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

// RightsNames is the inverse, rendered exactly as .NET renders
// ActiveDirectoryRights: walk the names by value descending, take each whose
// bits are all still present, clear them, then emit what was taken in
// ascending order.
//
// That is what collapses 0x000F01FF to "GenericAll" and 0x00020094 to
// "GenericRead" instead of to their constituent bits. The PowerShell backend
// gets these names from .NET itself, so any other rendering here is a
// permanent diff for a user switching backends — which is how the four-name
// spelling of GenericRead was found.
func RightsNames(mask uint32) []adcore.Right {
	taken := make([]bool, len(rightsTable))
	remaining := mask
	for i := len(rightsTable) - 1; i >= 0; i-- {
		r := rightsTable[i]
		if r.bit != 0 && remaining&r.bit == r.bit {
			taken[i] = true
			remaining &^= r.bit
		}
	}
	var out []adcore.Right
	for i, r := range rightsTable {
		if taken[i] {
			out = append(out, r.name)
		}
	}
	return out
}
