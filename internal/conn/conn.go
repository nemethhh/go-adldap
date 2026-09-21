// Package conn is the only place this module knows what LDAP library it uses.
//
// The types here are deliberately its own rather than the library's: the seam
// exists so that swapping go-ldap for a fork that supports SASL security
// layers and channel binding touches this package and nothing else. Every
// value is []byte, never string, because objectGUID, objectSid and
// nTSecurityDescriptor are binary and a string round trip corrupts them.
package conn

import "context"

type Scope int

const (
	ScopeBase Scope = iota
	ScopeOneLevel
	ScopeSubtree
)

type ModOp int

const (
	ModAdd ModOp = iota
	ModDelete
	ModReplace
)

// Attribute is one attribute and all its values, on an Add.
type Attribute struct {
	Type string
	Vals [][]byte
}

// Modification is one change on a Modify.
type Modification struct {
	Op   ModOp
	Type string
	Vals [][]byte
}

// Entry is one search result. Attrs holds raw values.
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

// First returns the first value of an attribute, or nil.
func (e Entry) First(attr string) []byte {
	if v := e.Attrs[attr]; len(v) > 0 {
		return v[0]
	}
	return nil
}

// FirstString returns the first value of an attribute as a string, or "".
// Use it only for attributes that are genuinely textual.
func (e Entry) FirstString(attr string) string { return string(e.First(attr)) }

// Control is an LDAP control to send with a request.
type Control struct {
	OID      string
	Critical bool
	Value    []byte
}

type SearchRequest struct {
	BaseDN     string
	Scope      Scope
	Filter     string
	Attributes []string
	SizeLimit  int
	Controls   []Control
}

type SearchResult struct {
	Entries  []Entry
	Controls []Control // response controls, e.g. the paging cookie
}

// RawError carries an LDAP result code and the server's diagnostic message,
// unclassified. Classification is the caller's job, above this seam, so that
// no LDAP library can reinterpret an AD refusal as a transport failure.
type RawError struct {
	ResultCode        uint16
	DiagnosticMessage string
	Err               error
}

func (e *RawError) Error() string { return e.DiagnosticMessage }
func (e *RawError) Unwrap() error { return e.Err }

// Conn is one bound LDAP connection.
type Conn interface {
	Search(ctx context.Context, req SearchRequest) (*SearchResult, error)
	Add(ctx context.Context, dn string, attrs []Attribute) error
	Modify(ctx context.Context, dn string, mods []Modification, controls ...Control) error
	ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error
	Delete(ctx context.Context, dn string) error
	Close() error
}

// SDFlagsControl is LDAP_SERVER_SD_FLAGS_OID, which scopes a read or write of
// nTSecurityDescriptor to the parts named.
//
// Without it a read returns the SACL too, which requires SeSecurityPrivilege
// the service account does not have, and a write replaces every part — so a
// caller holding only the DACL would blank the owner. The value is a BER
// SEQUENCE holding one INTEGER.
func SDFlagsControl(flags int) Control {
	return Control{
		OID:      "1.2.840.113556.1.4.801",
		Critical: true,
		Value:    []byte{0x30, 0x03, 0x02, 0x01, byte(flags)},
	}
}

// SDFlagDACL selects the discretionary ACL alone.
const SDFlagDACL = 0x04
