package conn

import (
	"context"
	"errors"

	"github.com/go-ldap/ldap/v3"
)

// goldapConn adapts github.com/go-ldap/ldap/v3 to Conn. This is the only file
// in the module that imports go-ldap; seam_test.go asserts it.
type goldapConn struct {
	l *ldap.Conn
}

var _ Conn = (*goldapConn)(nil)

// scopeToGoLDAP maps this package's Scope onto go-ldap's. The two happen to
// agree numerically today, but a cast would make that coincidence load-bearing
// across a library swap, which is precisely what this seam exists to prevent.
func scopeToGoLDAP(s Scope) int {
	switch s {
	case ScopeBase:
		return ldap.ScopeBaseObject
	case ScopeOneLevel:
		return ldap.ScopeSingleLevel
	default:
		return ldap.ScopeWholeSubtree
	}
}

// toRawError lifts a go-ldap error to the seam's own type, preserving the
// result code and the DC's diagnostic message verbatim. AD prefixes that
// message with the Win32 code in hex, which is what the classifier reads, so
// it must survive unedited.
func toRawError(err error) error {
	if err == nil {
		return nil
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		msg := le.Error()
		// The diagnostic the DC sent is the interesting half; go-ldap keeps
		// it on Err when it has one.
		if le.Err != nil {
			msg = le.Err.Error()
		}
		return &RawError{ResultCode: le.ResultCode, DiagnosticMessage: msg, Err: err}
	}
	return err
}

func (c *goldapConn) Search(ctx context.Context, req SearchRequest) (*SearchResult, error) {
	controls := make([]ldap.Control, 0, len(req.Controls))
	for _, ct := range req.Controls {
		controls = append(controls, ldap.NewControlString(ct.OID, ct.Critical, string(ct.Value)))
	}
	sr := ldap.NewSearchRequest(
		req.BaseDN, scopeToGoLDAP(req.Scope), ldap.NeverDerefAliases,
		req.SizeLimit, 0, false, req.Filter, req.Attributes, controls,
	)
	res, err := c.l.Search(sr)
	if err != nil {
		return nil, toRawError(err)
	}
	out := &SearchResult{Entries: make([]Entry, 0, len(res.Entries))}
	for _, e := range res.Entries {
		entry := Entry{DN: e.DN, Attrs: make(map[string][][]byte, len(e.Attributes))}
		for _, a := range e.Attributes {
			// ByteValues, never Values: objectGUID, objectSid and
			// nTSecurityDescriptor are binary and a string round trip
			// corrupts them.
			entry.Attrs[a.Name] = a.ByteValues
		}
		out.Entries = append(out.Entries, entry)
	}
	for _, ct := range res.Controls {
		out.Controls = append(out.Controls, controlFromGoLDAP(ct))
	}
	return out, nil
}

// controlFromGoLDAP carries the response control's encoded value back across
// the seam. Dropping it would lose the paged-search cookie, which is the one
// response control this module actually reads.
func controlFromGoLDAP(ct ldap.Control) Control {
	out := Control{OID: ct.GetControlType()}
	if p, ok := ct.(*ldap.ControlPaging); ok {
		out.Value = p.Cookie
	}
	return out
}

func (c *goldapConn) Add(ctx context.Context, dn string, attrs []Attribute) error {
	req := ldap.NewAddRequest(dn, nil)
	for _, a := range attrs {
		req.Attribute(a.Type, toStrings(a.Vals))
	}
	return toRawError(c.l.Add(req))
}

func (c *goldapConn) Modify(ctx context.Context, dn string, mods []Modification) error {
	req := ldap.NewModifyRequest(dn, nil)
	for _, m := range mods {
		vals := toStrings(m.Vals)
		switch m.Op {
		case ModAdd:
			req.Add(m.Type, vals)
		case ModDelete:
			req.Delete(m.Type, vals)
		default:
			req.Replace(m.Type, vals)
		}
	}
	return toRawError(c.l.Modify(req))
}

// toStrings converts raw values for go-ldap's string-valued request builders.
// It is byte-transparent: a Go string is an arbitrary byte sequence, so a
// unicodePwd or an nTSecurityDescriptor survives the round trip intact. The
// rule that matters is on the way back, where values must be read with
// ByteValues rather than Values.
func toStrings(vals [][]byte) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, string(v))
	}
	return out
}

func (c *goldapConn) ModifyDN(ctx context.Context, dn, newRDN string, deleteOldRDN bool, newSuperior string) error {
	return toRawError(c.l.ModifyDN(ldap.NewModifyDNRequest(dn, newRDN, deleteOldRDN, newSuperior)))
}

func (c *goldapConn) Delete(ctx context.Context, dn string) error {
	return toRawError(c.l.Del(ldap.NewDelRequest(dn, nil)))
}

func (c *goldapConn) Close() error { return c.l.Close() }
