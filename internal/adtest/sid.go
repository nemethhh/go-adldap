package adtest

import (
	"encoding/binary"
	"strings"

	"github.com/nemethhh/go-adldap/internal/attrs"
)

// DomainSID is the harness domain's own SID, S-1-5-21-1-2-3. It is what the
// naming context carries and what every principal's SID is built from, so the
// principal descriptors this module writes — gMSA membership and RBCD — have a
// real domain SID to name Domain Admins with.
var DomainSID = []byte{
	1, 4, 0, 0, 0, 0, 0, 5, // revision 1, four sub-authorities, authority 5
	21, 0, 0, 0,
	1, 0, 0, 0,
	2, 0, 0, 0,
	3, 0, 0, 0,
}

// principalSID appends a RID to the domain SID, the way a DC stamps one.
func principalSID(rid uint32) []byte {
	out := make([]byte, 0, len(DomainSID)+4)
	out = append(out, DomainSID...)
	out[1]++ // one more sub-authority
	return binary.LittleEndian.AppendUint32(out, rid)
}

// principalClasses are the object classes a DC gives an objectSid to. An OU
// gets none, which is why this is a check and not an unconditional stamp.
var principalClasses = map[string]bool{
	"user":                            true,
	"computer":                        true,
	"group":                           true,
	"msds-groupmanagedserviceaccount": true,
}

// stampSID gives a newly added entry an objectSid when its class calls for
// one, so a principal can be looked up by SID the way the RBCD and gMSA reads
// do.
func stampSID(entry map[string][][]byte, rid uint32) {
	for _, c := range entry["objectClass"] {
		if principalClasses[strings.ToLower(string(c))] {
			entry["objectSid"] = [][]byte{principalSID(rid)}
			return
		}
	}
}

// sidMatches compares a stored binary objectSid against a filter assertion.
//
// AD accepts the S-1-5-… text form in a filter against the binary attribute,
// and adcore.Equal emits exactly that, so a harness that compared raw bytes
// would never match a lookup by SID — and every principal read would report
// not-found.
func sidMatches(have []byte, want string) bool {
	s, err := attrs.SIDToString(have)
	if err != nil {
		return false
	}
	return strings.EqualFold(s, want)
}
