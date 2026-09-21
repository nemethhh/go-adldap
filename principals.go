package adldap

import (
	"context"
	"fmt"
	"sync"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/secdesc"
)

// domainSIDCache caches the domain SID for the client's lifetime. The DC is
// pinned and a domain's SID cannot change, so re-reading it on every RBCD or
// gMSA write would double the round trips for a value that is constant.
type domainSIDCache struct {
	once sync.Once
	sid  []byte
	err  error
}

// domainSID reads objectSid from the defaultNamingContext object.
func (c *core) domainSID(ctx context.Context, op string) ([]byte, error) {
	c.dsid.once.Do(func() {
		var e conn.Entry
		c.dsid.err = c.withConn(ctx, op, func(cn conn.Conn) error {
			res, err := cn.Search(ctx, conn.SearchRequest{
				BaseDN: c.dnc, Scope: conn.ScopeBase,
				Filter: "(objectClass=*)", Attributes: []string{"objectSid"}, SizeLimit: 1,
			})
			if err != nil {
				return err
			}
			if len(res.Entries) == 0 {
				return fmt.Errorf("the naming context %q returned no entry", c.dnc)
			}
			e = res.Entries[0]
			return nil
		})
		if c.dsid.err != nil {
			return
		}
		if c.dsid.sid = e.First("objectSid"); len(c.dsid.sid) == 0 {
			c.dsid.err = &adcore.Error{Kind: adcore.KindConstraint, Op: op,
				Err: fmt.Errorf("the naming context %q has no objectSid", c.dnc)}
		}
	})
	return c.dsid.sid, c.dsid.err
}

// principalSIDs resolves identities to the raw SIDs a principal descriptor
// holds. The object class is "*": a principal may be a user, a group, a
// computer or a gMSA, and classTerm treats "*" as "(objectClass=*)" while an
// empty string would build the filter "(objectClass=)", which matches nothing.
// A principal that resolves to nothing is an error naming it, never a
// silently shorter list: a descriptor missing a principal applies cleanly and
// then does not work, with nothing anywhere saying why.
func (c *core) principalSIDs(ctx context.Context, op string, ids []adcore.Identity) ([][]byte, error) {
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		e, err := c.getOne(ctx, op, id, "*", []string{"objectSid"})
		if err != nil {
			if isNotFound(err) {
				return nil, &adcore.Error{
					Kind: adcore.KindNotFound, Op: op, Identity: id.String(),
					Err: fmt.Errorf("principal %q does not exist", adcore.IdentityArg(id)),
				}
			}
			return nil, err
		}
		sid := e.First("objectSid")
		if len(sid) == 0 {
			return nil, &adcore.Error{
				Kind: adcore.KindConstraint, Op: op, Identity: id.String(),
				Err: fmt.Errorf("principal %q has no objectSid", adcore.IdentityArg(id)),
			}
		}
		out = append(out, sid)
	}
	return out, nil
}

// principalGUIDs is the read direction: descriptor bytes to the object GUIDs
// the model carries. A SID that resolves to nothing is skipped rather than
// failing the read — an account deleted out from under the delegation is a
// real state, and refusing to read the object because of it would make the
// drift impossible to see or to correct.
func (c *core) principalGUIDs(ctx context.Context, op string, sd []byte) ([]string, error) {
	sids, err := secdesc.PrincipalSIDs(sd)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	var out []string
	for _, raw := range sids {
		s, err := attrs.SIDToString(raw)
		if err != nil {
			continue
		}
		e, err := c.getOne(ctx, op, adcore.BySID(s), "*", []string{"objectGUID"})
		if err != nil {
			if isNotFound(err) {
				continue
			}
			return nil, err
		}
		guid, err := attrs.GUIDToString(e.First("objectGUID"))
		if err != nil {
			continue
		}
		out = append(out, guid)
	}
	return out, nil
}

// principalSDValue builds the attribute value for a set of principals.
func (c *core) principalSDValue(ctx context.Context, op string, ids []adcore.Identity) ([]byte, error) {
	dsid, err := c.domainSID(ctx, op)
	if err != nil {
		return nil, err
	}
	sids, err := c.principalSIDs(ctx, op, ids)
	if err != nil {
		return nil, err
	}
	sd, err := secdesc.BuildPrincipalSD(dsid, sids)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	return sd, nil
}
