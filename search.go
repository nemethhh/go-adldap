package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

// Microsoft LDAP control OIDs.
const (
	ControlPaging      = "1.2.840.113556.1.4.319"
	ControlShowDeleted = "1.2.840.113556.1.4.417"
	ControlSDFlags     = "1.2.840.113556.1.4.801"
	ControlExtendedDN  = "1.2.840.113556.1.4.529"
)

// MatchingRuleInChain is LDAP_MATCHING_RULE_IN_CHAIN, which walks nested
// group membership server-side.
const MatchingRuleInChain = "1.2.840.113556.1.4.1941"

func scopeOf(s adcore.SearchScope) conn.Scope {
	switch s {
	case adcore.SearchScopeBase:
		return conn.ScopeBase
	case adcore.SearchScopeOneLevel:
		return conn.ScopeOneLevel
	default:
		return conn.ScopeSubtree
	}
}

// searchEntries runs a class-scoped search. It asks for SizeLimit+1 rows, so
// finding the extra one proves more exist and the caller errors rather than
// returning a silently truncated set — the same contract the PowerShell
// backend has.
func (c *core) searchEntries(ctx context.Context, op string, q adcore.Query, objectClass string, want []string) ([]conn.Entry, error) {
	q = q.WithDefaults(c.dnc)

	filter := adcore.Equal("objectClass", objectClass)
	if q.Filter != "" {
		filter = adcore.And(filter, q.Filter)
	}

	var entries []conn.Entry
	err := c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN:     q.SearchBase,
			Scope:      scopeOf(q.Scope),
			Filter:     filter,
			Attributes: want,
			SizeLimit:  q.SizeLimit + 1,
		})
		if err != nil {
			return err
		}
		entries = res.Entries
		return nil
	})
	// A server that enforces the size limit itself answers sizeLimitExceeded
	// instead of returning the extra row. That is the same condition, so it
	// must produce the same Kind — and it already does, since result code 4
	// classifies as KindTooManyResults. Re-stamp the message so both paths
	// read alike.
	if err != nil {
		var e *adcore.Error
		if asError(err, &e) && e.Kind == adcore.KindTooManyResults {
			return nil, tooMany(op, q.SizeLimit)
		}
		return nil, err
	}
	if len(entries) > q.SizeLimit {
		return nil, tooMany(op, q.SizeLimit)
	}
	return entries, nil
}

func tooMany(op string, limit int) error {
	return &adcore.Error{
		Kind: adcore.KindTooManyResults, Op: op,
		Err: fmt.Errorf("more than %d objects matched; narrow the filter or raise the limit", limit),
	}
}

// identityFilter turns an Identity into the filter that finds exactly it.
// Every value is escaped; a GUID becomes its binary search form, which is how
// AD matches objectGUID.
func identityFilter(id adcore.Identity) (string, error) {
	arg := adcore.IdentityArg(id)
	switch adcore.IdentityForm(id) {
	case "guid":
		b, err := attrs.GUIDToBytes(arg)
		if err != nil {
			return "", err
		}
		return "(objectGUID=" + escapeBinary(b) + ")", nil
	case "sid":
		return adcore.Equal("objectSid", arg), nil
	case "sam":
		return adcore.Equal("sAMAccountName", arg), nil
	default:
		return adcore.Equal("distinguishedName", arg), nil
	}
}

// escapeBinary renders bytes as the \xx form an LDAP filter requires.
func escapeBinary(b []byte) string {
	out := make([]byte, 0, len(b)*3)
	const hex = "0123456789abcdef"
	for _, x := range b {
		out = append(out, '\\', hex[x>>4], hex[x&0x0f])
	}
	return string(out)
}

// getOne reads exactly one object of a class by identity. A search returning
// nothing is KindNotFound; returning more than one is KindConstraint, never a
// silent first-match.
func (c *core) getOne(ctx context.Context, op string, id adcore.Identity, objectClass string, want []string) (conn.Entry, error) {
	f, err := identityFilter(id)
	if err != nil {
		return conn.Entry{}, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Err: err}
	}
	filter := adcore.And(adcore.Equal("objectClass", objectClass), f)

	var entries []conn.Entry
	err = c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN:     c.dnc,
			Scope:      conn.ScopeSubtree,
			Filter:     filter,
			Attributes: want,
			SizeLimit:  2,
		})
		if err != nil {
			return err
		}
		entries = res.Entries
		return nil
	})
	if err != nil {
		// A base-scoped read of a DN that is gone comes back noSuchObject;
		// that is this identity not being found, not a failure of the search.
		var e *adcore.Error
		if asError(err, &e) && e.Kind == adcore.KindNotFound {
			return conn.Entry{}, notFound(op, id, objectClass)
		}
		return conn.Entry{}, adcore.WithIdentity(err, op, id)
	}
	switch len(entries) {
	case 1:
		return entries[0], nil
	case 0:
		return conn.Entry{}, notFound(op, id, objectClass)
	default:
		return conn.Entry{}, &adcore.Error{
			Kind: adcore.KindConstraint, Op: op, Identity: id.String(),
			Err: fmt.Errorf("%d objects match %s; the identity is ambiguous", len(entries), id),
		}
	}
}

func notFound(op string, id adcore.Identity, objectClass string) error {
	what := objectClass
	if what == "*" {
		what = "object"
	}
	return &adcore.Error{
		Kind: adcore.KindNotFound, Op: op, Identity: id.String(),
		Err: fmt.Errorf("no %s matches %s", what, id),
	}
}

// resolveDN finds an object's DN by identity, for the operations that address
// by DN — Modify, ModifyDN and Delete.
func (c *core) resolveDN(ctx context.Context, op string, id adcore.Identity) (string, error) {
	if adcore.IdentityForm(id) == "dn" {
		return adcore.IdentityArg(id), nil
	}
	e, err := c.getOne(ctx, op, id, "*", []string{"distinguishedName"})
	if err != nil {
		return "", err
	}
	return e.DN, nil
}
