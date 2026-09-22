package adtest

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/conn"
)

// MemServer is an in-memory directory reached through a conn.Conn rather than
// a socket.
//
// It exists for one reason: gldap, which backs the wire harness above, parses
// no ModifyDN request — its requestType switch rejects application 12 outright
// — so a rename or a move cannot be served there at all. Everything above the
// go-ldap adapter is still the real implementation, so the CRUD semantics and
// the conformance suite are exercised for real; what this does not cover is
// the adapter and the socket, which Start does.
type MemServer struct {
	mu         sync.Mutex
	entries    map[string]map[string][][]byte
	seq        uint32
	rangeLimit int
}

// StartMemory returns an empty in-memory directory holding only the naming
// context.
func StartMemory(t *testing.T) *MemServer {
	t.Helper()
	m := &MemServer{entries: map[string]map[string][][]byte{}}
	m.Seed(DNC, map[string][][]byte{
		"objectClass":       {[]byte("top"), []byte("domainDNS")},
		"distinguishedName": {[]byte(DNC)},
		// The naming context carries the domain SID. Every principal
		// descriptor is built from it, so without one the gMSA and RBCD
		// writes have nothing to name Domain Admins with.
		"objectSid": {DomainSID},
	})
	return m
}

// RangeLimit makes the server behave like a domain controller's MaxValRange:
// a multi-valued attribute is returned in pages, and the attribute name in the
// result carries the range the page covers. Without this the harness hands
// back every value at once and no ranged-retrieval bug can be reproduced in
// CI — which is exactly the shape of bug that only a real group with more than
// 1500 members would otherwise find.
func (m *MemServer) RangeLimit(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rangeLimit = n
}

// Seed inserts an entry directly.
func (m *MemServer) Seed(dn string, attrs map[string][][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[dn] = attrs
}

// Entries returns a snapshot for assertions.
func (m *MemServer) Entries() map[string]map[string][][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]map[string][][]byte, len(m.entries))
	for dn, attrs := range m.entries {
		c := make(map[string][][]byte, len(attrs))
		for k, v := range attrs {
			c[k] = append([][]byte(nil), v...)
		}
		out[dn] = c
	}
	return out
}

// Client builds a Client over this directory.
func (m *MemServer) Client(t *testing.T) *adldap.Client {
	t.Helper()
	client, err := adldap.NewWithConn(context.Background(), adldap.Config{
		Server:   "mem.corp.local",
		TLS:      adldap.TLSLDAPS,
		Kerberos: &adldap.KerberosAuth{}, // never used; NewWithConn does not bind
	}, func(context.Context) (conn.Conn, error) {
		return &memConn{m: m}, nil
	})
	if err != nil {
		t.Fatalf("adldap.NewWithConn: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// Directory is the shorthand the conformance suite uses.
func (m *MemServer) Directory(t *testing.T) adcore.Directory {
	t.Helper()
	return m.Client(t).Directory()
}

// nextGUID hands out a distinct objectGUID, the way a DC stamps one on create.
func (m *MemServer) nextGUID() []byte {
	m.seq++
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], m.seq)
	return b
}

type memConn struct{ m *MemServer }

var _ conn.Conn = (*memConn)(nil)

func (c *memConn) Close() error { return nil }

func raw(code uint16, diagnostic string) error {
	return &conn.RawError{ResultCode: code, DiagnosticMessage: diagnostic}
}

// AD's own diagnostics, so the classifier sees in these tests exactly what it
// sees against a domain.
const (
	diagNoObject      = "0000208D: NameErr: DSID-03100238, problem 2001 (NO_OBJECT), data 0"
	diagEntryExists   = "00002071: UpdErr: DSID-030F1173, problem 6005 (ENTRY_EXISTS), data 0"
	diagNotOnNonLeaf  = "00002015: UpdErr: DSID-030F1219, problem 6003 (NOT_ALLOWED_ON_NON_LEAF), data 0"
	diagSizeLimitHint = "00000004: SizeLimit exceeded"
)

func (c *memConn) Search(ctx context.Context, req conn.SearchRequest) (*conn.SearchResult, error) {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()

	if req.BaseDN == "" && req.Scope == conn.ScopeBase {
		return &conn.SearchResult{Entries: []conn.Entry{{
			DN: "",
			Attrs: map[string][][]byte{
				"defaultNamingContext":       {[]byte(DNC)},
				"dnsHostName":                {[]byte("dc01.corp.local")},
				"schemaNamingContext":        {[]byte("CN=Schema,CN=Configuration," + DNC)},
				"configurationNamingContext": {[]byte("CN=Configuration," + DNC)},
			},
		}}}, nil
	}

	showDeleted := hasControl(req.Controls, adldap.ControlShowDeleted)

	var out []conn.Entry
	for dn, attrs := range c.m.entries {
		if !inScopeMem(dn, req.BaseDN, req.Scope) {
			continue
		}
		// A tombstone is invisible without the show-deleted control, exactly
		// as a DC hides it. Returning them unconditionally would let the
		// tombstone probe pass while never sending the control.
		if isTombstone(attrs) && !showDeleted {
			continue
		}
		if !matchFilter(req.Filter, attrs) {
			continue
		}
		out = append(out, conn.Entry{DN: dn, Attrs: rangePages(project(attrs, req.Attributes), req.Attributes, c.m.rangeLimit)})
	}
	if len(out) == 0 && req.Scope == conn.ScopeBase && !c.existsLocked(req.BaseDN) {
		return nil, raw(32, diagNoObject)
	}
	// A real DC stops at the limit and says so rather than returning a short
	// answer, so the caller's more-than-the-limit check has something to see.
	if req.SizeLimit > 0 && len(out) > req.SizeLimit {
		return &conn.SearchResult{Entries: out[:req.SizeLimit]}, raw(4, diagSizeLimitHint)
	}
	return &conn.SearchResult{Entries: out}, nil
}

func (c *memConn) existsLocked(dn string) bool {
	for have := range c.m.entries {
		if equalFoldDN(have, dn) {
			return true
		}
	}
	return false
}

func (c *memConn) keyLocked(dn string) string {
	for have := range c.m.entries {
		if equalFoldDN(have, dn) {
			return have
		}
	}
	return ""
}

func project(attrs map[string][][]byte, want []string) map[string][][]byte {
	out := make(map[string][][]byte, len(attrs))
	for k, v := range attrs {
		if len(want) == 0 {
			out[k] = v
			continue
		}
		for _, w := range want {
			// A requested "member;range=0-*" asks for the "member" attribute;
			// the range is an option on the description, not part of the name.
			if w == "*" || strings.EqualFold(baseAttr(w), k) {
				out[k] = v
				break
			}
		}
	}
	return out
}

// baseAttr strips any options from an attribute description, so
// "member;range=1500-*" selects "member".
func baseAttr(desc string) string {
	if i := strings.Index(desc, ";"); i >= 0 {
		return desc[:i]
	}
	return desc
}

// rangePages re-keys a requested attribute as a page of values, the way a
// domain controller does once a value count passes MaxValRange.
//
// AD answers "member;range=0-*" with "member;range=0-1499" while values
// remain and with "member;range=<lo>-*" on the last page — the "*" in the
// RESPONSE is the terminator, and it is deliberately emitted here even when
// the final page is exactly full, because that is the case a client counting
// values against the limit gets wrong.
func rangePages(attrs map[string][][]byte, want []string, limit int) map[string][][]byte {
	if limit <= 0 {
		return attrs
	}
	out := make(map[string][][]byte, len(attrs))
	for k, v := range attrs {
		out[k] = v
	}
	for _, w := range want {
		base := baseAttr(w)
		vals, ok := attrs[base]
		if !ok || len(vals) <= limit {
			continue
		}
		lo := 0
		if i := strings.Index(strings.ToLower(w), ";range="); i >= 0 {
			spec := w[i+len(";range="):]
			if j := strings.Index(spec, "-"); j >= 0 {
				if n, err := strconv.Atoi(spec[:j]); err == nil {
					lo = n
				}
			}
		}
		if lo > len(vals) {
			lo = len(vals)
		}
		hi := lo + limit
		delete(out, base)
		if hi >= len(vals) {
			out[fmt.Sprintf("%s;range=%d-*", base, lo)] = vals[lo:]
			continue
		}
		out[fmt.Sprintf("%s;range=%d-%d", base, lo, hi-1)] = vals[lo:hi]
	}
	return out
}

func inScopeMem(dn, base string, scope conn.Scope) bool {
	switch scope {
	case conn.ScopeBase:
		return equalFoldDN(dn, base)
	case conn.ScopeOneLevel:
		return isChildOf(dn, base)
	default:
		return isUnder(dn, base)
	}
}

func (c *memConn) Add(ctx context.Context, dn string, add []conn.Attribute) error {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	if c.existsLocked(dn) {
		return raw(68, diagEntryExists)
	}
	attrs := make(map[string][][]byte, len(add)+3)
	for _, a := range add {
		attrs[a.Type] = a.Vals
	}
	// A DC stamps these; a client never sends them.
	attrs["objectGUID"] = [][]byte{c.m.nextGUID()}
	attrs["nTSecurityDescriptor"] = [][]byte{emptyDescriptor()}
	attrs["distinguishedName"] = [][]byte{[]byte(dn)}
	attrs["name"] = [][]byte{[]byte(rdnValue(dn))}
	stampSID(attrs, 1000+c.m.seq)
	c.m.entries[dn] = attrs
	return nil
}

// rdnValue is the value half of a DN's first component, unescaped.
func rdnValue(dn string) string {
	parts, err := adcore.SplitDN(dn)
	if err != nil || len(parts) == 0 {
		return ""
	}
	i := strings.Index(parts[0], "=")
	if i < 0 {
		return ""
	}
	return strings.ReplaceAll(parts[0][i+1:], `\`, "")
}

func (c *memConn) Modify(ctx context.Context, dn string, mods []conn.Modification, _ ...conn.Control) error {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	key := c.keyLocked(dn)
	if key == "" {
		return raw(32, diagNoObject)
	}
	for _, mod := range mods {
		name := attrKey(c.m.entries[key], mod.Type)
		switch mod.Op {
		case conn.ModAdd:
			c.m.entries[key][name] = append(c.m.entries[key][name], mod.Vals...)
		case conn.ModDelete:
			if len(mod.Vals) == 0 {
				delete(c.m.entries[key], name)
				continue
			}
			c.m.entries[key][name] = without(c.m.entries[key][name], mod.Vals)
		default:
			if len(mod.Vals) == 0 {
				delete(c.m.entries[key], name)
				continue
			}
			c.m.entries[key][name] = mod.Vals
		}
	}
	return nil
}

// attrKey returns the existing spelling of an attribute name, so a modify does
// not create a second entry differing only in case.
func attrKey(attrs map[string][][]byte, name string) string {
	for k := range attrs {
		if strings.EqualFold(k, name) {
			return k
		}
	}
	return name
}

// ModifyDN is the operation the wire harness cannot serve. It renames and
// moves in one step, keeping the objectGUID — which is the whole property the
// contract cares about.
func (c *memConn) ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()

	key := c.keyLocked(dn)
	if key == "" {
		return raw(32, diagNoObject)
	}
	parent := newSuperior
	if parent == "" {
		p, err := adcore.ContainerOf(key)
		if err != nil {
			return raw(34, "00000034: invalid DN syntax")
		}
		parent = p
	}
	target := newRDN + "," + parent
	if !equalFoldDN(target, key) && c.existsLocked(target) {
		return raw(68, diagEntryExists)
	}

	attrs := c.m.entries[key]
	delete(c.m.entries, key)
	attrs["distinguishedName"] = [][]byte{[]byte(target)}
	attrs["name"] = [][]byte{[]byte(rdnValue(target))}
	c.m.entries[target] = attrs

	// Every descendant's DN moves with it, exactly as a directory reparents a
	// subtree. Without this a move would strand children at a DN whose parent
	// no longer exists.
	for childDN, childAttrs := range c.m.entries {
		if childDN == target || !isUnder(childDN, key) {
			continue
		}
		suffix := childDN[:len(childDN)-len(key)]
		moved := suffix + target
		delete(c.m.entries, childDN)
		childAttrs["distinguishedName"] = [][]byte{[]byte(moved)}
		c.m.entries[moved] = childAttrs
	}
	return nil
}

func (c *memConn) Delete(ctx context.Context, dn string) error {
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	key := c.keyLocked(dn)
	if key == "" {
		return raw(32, diagNoObject)
	}
	for other := range c.m.entries {
		if other != key && isUnder(other, key) {
			return raw(66, diagNotOnNonLeaf)
		}
	}
	delete(c.m.entries, key)
	return nil
}

func hasControl(controls []conn.Control, oid string) bool {
	for _, c := range controls {
		if c.OID == oid {
			return true
		}
	}
	return false
}

func isTombstone(attrs map[string][][]byte) bool {
	vals, ok := lookupFold(attrs, "isDeleted")
	return ok && len(vals) > 0 && strings.EqualFold(string(vals[0]), "TRUE")
}

// emptyDescriptor is a minimal self-relative security descriptor with an empty
// DACL, which is what a freshly created object effectively presents to the
// protection code. Built here rather than imported so the harness does not
// depend on the package under test.
func emptyDescriptor() []byte {
	acl := make([]byte, 8)
	acl[0] = 2 // ACL_REVISION
	binary.LittleEndian.PutUint16(acl[2:4], 8)
	binary.LittleEndian.PutUint16(acl[4:6], 0)

	sd := make([]byte, 20)
	sd[0] = 1                                          // revision
	binary.LittleEndian.PutUint16(sd[2:4], 0x8000|0x4) // self-relative, DACL present
	binary.LittleEndian.PutUint32(sd[16:20], 20)       // OffsetDacl
	return append(sd, acl...)
}
