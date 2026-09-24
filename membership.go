package adldap

import (
	"context"
	"strings"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

var memberAttrs = []string{"objectGUID", "distinguishedName", "objectClass", "objectSid"}

// Members reads a group's direct membership, following ranged retrieval so a
// group past the domain controller's MaxValRange reads completely.
//
// Truncating would be worse than failing: Terraform would read a short list,
// compare it to configuration, and plan the removal of members that exist.
// That is why this replaced a refusal rather than a silent cap.
func (g *groupDirectory) Members(ctx context.Context, id adcore.Identity) ([]adcore.Member, error) {
	const op = "Group.Members"
	// The DN is resolved first because ranged retrieval is a base-scoped read
	// per page and every page must name the same object.
	dn, err := g.c.resolveDN(ctx, op, id)
	if err != nil {
		return nil, err
	}
	dns, err := g.c.rangedValues(ctx, op, dn, "member")
	if err != nil {
		return nil, adcore.WithIdentity(err, op, id)
	}
	return g.resolveMembers(ctx, op, dns)
}

// MembersRecursive resolves nested membership server-side.
//
// LDAP_MATCHING_RULE_IN_CHAIN returns nested groups as well as leaf accounts,
// where Get-ADGroupMember -Recursive returns only leaf user and computer
// accounts. This filters to leaves so the two backends agree — otherwise a
// user switching backends would see every nested group appear in state.
func (g *groupDirectory) MembersRecursive(ctx context.Context, id adcore.Identity) ([]adcore.Member, error) {
	const op = "Group.MembersRecursive"
	target, err := g.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	// memberOf, not member. The matching rule walks whichever attribute it is
	// applied to: "member:...:=X" finds the groups that contain X, which is the
	// inverse of this question and returns nothing for a leaf account. The lab
	// caught this as an empty recursive membership where one member existed.
	filter := "(&(|(objectClass=user)(objectClass=computer))(memberOf:" +
		MatchingRuleInChain + ":=" + adcore.EscapeFilter(target.DN) + "))"

	var entries []conn.Entry
	err = g.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: g.c.dnc, Scope: conn.ScopeSubtree,
			Filter: filter, Attributes: memberAttrs,
		})
		if err != nil {
			return err
		}
		entries = res.Entries
		return nil
	})
	if err != nil {
		return nil, adcore.WithIdentity(err, op, id)
	}
	return g.modelMembers(entries)
}

func (g *groupDirectory) AddMembers(ctx context.Context, id adcore.Identity, members []adcore.Identity) error {
	return g.editMembers(ctx, "Group.AddMembers", id, members, conn.ModAdd)
}

func (g *groupDirectory) RemoveMembers(ctx context.Context, id adcore.Identity, members []adcore.Identity) error {
	return g.editMembers(ctx, "Group.RemoveMembers", id, members, conn.ModDelete)
}

// alreadySatisfied reports whether AD's refusal means the desired state
// already holds: an add of an existing member, or a removal of a non-member.
//
// Terraform re-applies, so both must converge rather than fail. The conditions
// are recognized by AD's own diagnostic text, which the classifier preserves
// verbatim on ServerMessage.
func alreadySatisfied(e *adcore.Error, modOp conn.ModOp) bool {
	msg := e.ServerMessage
	if modOp == conn.ModAdd {
		return strings.Contains(msg, "ENTRY_EXISTS") ||
			strings.Contains(msg, "ATT_OR_VALUE_EXISTS") ||
			e.Code == 0x207E // ERROR_DS_ATT_ALREADY_EXISTS
	}
	return strings.Contains(msg, "NO_ATTRIBUTE_OR_VAL") ||
		strings.Contains(msg, "NO_ATT_OR_VAL") ||
		e.Code == 0x2076 // ERROR_DS_ATT_IS_NOT_ON_OBJ
}

// editMembers adds or removes members, one round trip for the whole set.
func (g *groupDirectory) editMembers(ctx context.Context, op string, id adcore.Identity, members []adcore.Identity, modOp conn.ModOp) error {
	if len(members) == 0 {
		return nil
	}

	unlock := g.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	target, err := g.Get(ctx, id)
	if err != nil {
		return err
	}

	vals := make([][]byte, 0, len(members))
	for _, m := range members {
		dn, err := g.c.resolveDN(ctx, op, m)
		if err != nil {
			return err
		}
		vals = append(vals, []byte(dn))
	}

	err = g.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Modify(ctx, target.DN, []conn.Modification{{Op: modOp, Type: "member", Vals: vals}})
	})
	if err == nil {
		return nil
	}

	var e *adcore.Error
	if asError(err, &e) &&
		(e.Kind == adcore.KindConstraint || e.Kind == adcore.KindAlreadyExists) &&
		alreadySatisfied(e, modOp) {
		return nil
	}
	return adcore.WithIdentity(err, op, id)
}

// IsMember answers direct membership with a base-scoped search rather than by
// reading the whole member attribute, so a large group costs nothing.
func (g *groupDirectory) IsMember(ctx context.Context, id adcore.Identity, member adcore.Identity) (bool, error) {
	const op = "Group.IsMember"
	target, err := g.Get(ctx, id)
	if err != nil {
		return false, err
	}
	memberDN, err := g.c.resolveDN(ctx, op, member)
	if err != nil {
		return false, err
	}

	var found bool
	err = g.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: target.DN, Scope: conn.ScopeBase,
			Filter:     adcore.Equal("member", memberDN),
			Attributes: []string{"distinguishedName"}, SizeLimit: 1,
		})
		if err != nil {
			return err
		}
		found = len(res.Entries) > 0
		return nil
	})
	if err != nil {
		return false, adcore.WithIdentity(err, op, id)
	}
	return found, nil
}

// resolveMembers reads each member DN back as a model.
func (g *groupDirectory) resolveMembers(ctx context.Context, op string, dns [][]byte) ([]adcore.Member, error) {
	if len(dns) == 0 {
		return []adcore.Member{}, nil
	}
	terms := make([]string, 0, len(dns))
	for _, dn := range dns {
		terms = append(terms, adcore.Equal("distinguishedName", string(dn)))
	}
	filter := "(|" + strings.Join(terms, "") + ")"

	var entries []conn.Entry
	err := g.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: g.c.dnc, Scope: conn.ScopeSubtree,
			Filter: filter, Attributes: memberAttrs, SizeLimit: len(dns),
		})
		if err != nil {
			return err
		}
		entries = res.Entries
		return nil
	})
	if err != nil {
		return nil, err
	}
	return g.modelMembers(entries)
}

func (g *groupDirectory) modelMembers(entries []conn.Entry) ([]adcore.Member, error) {
	out := make([]adcore.Member, 0, len(entries))
	for _, e := range entries {
		guid, err := attrs.GUIDToString(e.First("objectGUID"))
		if err != nil {
			return nil, err
		}
		sid := ""
		if raw := e.First("objectSid"); len(raw) > 0 {
			if sid, err = attrs.SIDToString(raw); err != nil {
				return nil, err
			}
		}
		class := ""
		if classes := e.Attrs["objectClass"]; len(classes) > 0 {
			class = string(classes[len(classes)-1]) // the most derived class
		}
		out = append(out, adcore.Member{GUID: guid, DN: e.DN, Class: class, SID: sid})
	}
	return out, nil
}
