package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

type schemaDirectory struct{ c *core }

var _ adcore.SchemaDirectory = (*schemaDirectory)(nil)

// Resolve turns friendly names into GUIDs, one search per reference that
// needs one.
//
// A reference whose name is already a GUID is passed through untouched: the
// provider accepts either form, and searching the directory for a value that
// is already the answer costs a round trip per ACE on every plan.
func (s *schemaDirectory) Resolve(ctx context.Context, refs []adcore.SchemaRef) (map[adcore.SchemaRef]string, error) {
	const op = "Schema.Resolve"
	out := make(map[adcore.SchemaRef]string, len(refs))
	for _, ref := range refs {
		if _, ok := out[ref]; ok {
			continue // the same name twice is one search
		}
		if isGUIDString(ref.Name) {
			out[ref] = ref.Name
			continue
		}
		guid, err := s.resolveOne(ctx, op, ref)
		if err != nil {
			return nil, err
		}
		out[ref] = guid
	}
	return out, nil
}

func (s *schemaDirectory) resolveOne(ctx context.Context, op string, ref adcore.SchemaRef) (string, error) {
	var (
		base, filter, attr string
		binaryGUID         bool
	)
	switch ref.Kind {
	case adcore.RefAttribute:
		base = s.c.schemaNC
		filter = "(&(objectClass=attributeSchema)" + adcore.Equal("lDAPDisplayName", ref.Name) + ")"
		attr, binaryGUID = "schemaIDGUID", true
	case adcore.RefClass:
		base = s.c.schemaNC
		filter = "(&(objectClass=classSchema)" + adcore.Equal("lDAPDisplayName", ref.Name) + ")"
		attr, binaryGUID = "schemaIDGUID", true
	case adcore.RefExtendedRight:
		base = "CN=Extended-Rights," + s.c.configNC
		filter = "(&(objectClass=controlAccessRight)" + adcore.Equal("displayName", ref.Name) + ")"
		// rightsGUID is a STRING attribute, not an octet string. Formatting
		// its bytes as a binary GUID yields a well-formed value that matches
		// nothing, and the ACE built from it grants a right nobody asked for.
		attr, binaryGUID = "rightsGUID", false
	default:
		return "", &adcore.Error{Kind: adcore.KindConstraint, Op: op,
			Err: fmt.Errorf("unknown schema reference kind %q", string(ref.Kind))}
	}

	var entries []conn.Entry
	if err := s.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: base, Scope: conn.ScopeSubtree, Filter: filter,
			Attributes: []string{attr}, SizeLimit: 2,
		})
		if err != nil {
			return err
		}
		entries = res.Entries
		return nil
	}); err != nil {
		return "", err
	}

	switch len(entries) {
	case 0:
		// Omitting it from the map instead would leave the caller building an
		// ACE with an empty object type — which means "all properties", very
		// much more than was asked for.
		return "", &adcore.Error{Kind: adcore.KindNotFound, Op: op,
			Err: fmt.Errorf("no %s named %q exists in the schema", string(ref.Kind), ref.Name)}
	case 1:
	default:
		return "", &adcore.Error{Kind: adcore.KindConstraint, Op: op,
			Err: fmt.Errorf("%q matches %d schema objects", ref.Name, len(entries))}
	}

	raw := entries[0].First(attr)
	if len(raw) == 0 {
		return "", &adcore.Error{Kind: adcore.KindConstraint, Op: op,
			Err: fmt.Errorf("%q has no %s", ref.Name, attr)}
	}
	if !binaryGUID {
		return string(raw), nil
	}
	guid, err := attrs.GUIDToString(raw)
	if err != nil {
		return "", &adcore.Error{Kind: adcore.KindConstraint, Op: op,
			Err: fmt.Errorf("%s of %q is not a GUID: %w", attr, ref.Name, err)}
	}
	return guid, nil
}

// isGUIDString reports whether a name is already the canonical 8-4-4-4-12
// form, in which case it needs no resolution.
func isGUIDString(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
