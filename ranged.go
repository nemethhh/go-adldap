package adldap

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
)

// rangedValues reads every value of a multi-valued attribute, following AD's
// ranged retrieval when the domain controller pages it.
//
// The terminator is the "*" the server puts in the response range, never a
// short page: the final page can be exactly the page size, and counting
// values against the limit silently drops everything after it.
func (c *core) rangedValues(ctx context.Context, op, dn, attr string) ([][]byte, error) {
	var out [][]byte
	lo := 0
	for {
		want := fmt.Sprintf("%s;range=%d-*", attr, lo)

		var e conn.Entry
		if err := c.withConn(ctx, op, func(cn conn.Conn) error {
			res, err := cn.Search(ctx, conn.SearchRequest{
				BaseDN: dn, Scope: conn.ScopeBase,
				Filter: "(objectClass=*)", Attributes: []string{want}, SizeLimit: 1,
			})
			if err != nil {
				return err
			}
			if len(res.Entries) == 0 {
				return &adcore.Error{Kind: adcore.KindNotFound, Op: op, Target: dn,
					Err: fmt.Errorf("the object disappeared while its %s was being read", attr)}
			}
			e = res.Entries[0]
			return nil
		}); err != nil {
			return nil, err
		}

		key, last, err := findRangedAttr(e, attr)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Target: dn, Err: err}
		}
		vals := e.Attrs[key]
		out = append(out, vals...)
		if last || len(vals) == 0 {
			return out, nil
		}
		lo += len(vals)
	}
}

// findRangedAttr locates the attribute in a result whose key may carry a
// range option, and reports whether it is the final page.
//
// AD answers "member;range=0-*" with "member;range=0-1499" while values
// remain and "member;range=1500-*" on the last page. A server that returns
// the bare attribute name has given everything at once, which is also a final
// page.
func findRangedAttr(e conn.Entry, attr string) (key string, last bool, err error) {
	if _, ok := e.Attrs[attr]; ok {
		return attr, true, nil
	}
	prefix := strings.ToLower(attr) + ";range="
	for k := range e.Attrs {
		lk := strings.ToLower(k)
		if !strings.HasPrefix(lk, prefix) {
			continue
		}
		spec := lk[len(prefix):]
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return "", false, fmt.Errorf("malformed range option %q on %s", spec, attr)
		}
		if parts[1] == "*" {
			return k, true, nil
		}
		if _, convErr := strconv.Atoi(parts[1]); convErr != nil {
			return "", false, fmt.Errorf("malformed range upper bound %q on %s", parts[1], attr)
		}
		return k, false, nil
	}
	// No values at all is an empty attribute, which is a legitimate state.
	return attr, true, nil
}
