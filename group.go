package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

var groupAttrs = []string{
	"objectGUID", "distinguishedName", "name", "sAMAccountName",
	"description", "groupType", "objectSid", "managedBy",
}

type groupDirectory struct{ c *core }

var _ adcore.GroupDirectory = (*groupDirectory)(nil)

// cnRDN builds a CN RDN, escaping the name per RFC 4514 for the same reason
// ouRDN does.
func cnRDN(name string) string { return "CN=" + adcore.EscapeValue(name) }

func (g *groupDirectory) model(e conn.Entry) (*adcore.Group, error) {
	guid, err := attrs.GUIDToString(e.First("objectGUID"))
	if err != nil {
		return nil, err
	}
	container, err := adcore.ContainerOf(e.DN)
	if err != nil {
		return nil, err
	}
	sid := ""
	if raw := e.First("objectSid"); len(raw) > 0 {
		if sid, err = attrs.SIDToString(raw); err != nil {
			return nil, err
		}
	}
	// groupType arrives as a signed decimal string; parsing it unsigned fails
	// outright for a security group, whose high bit is set.
	gt, err := attrs.ParseGroupType(e.FirstString("groupType"))
	if err != nil {
		return nil, err
	}
	scope, category := attrs.ScopeAndCategory(gt)

	return &adcore.Group{
		GUID: guid, DN: e.DN, Name: e.FirstString("name"),
		SamAccountName: e.FirstString("sAMAccountName"),
		Container:      container,
		Scope:          scope, Category: category,
		Description: e.FirstString("description"),
		ManagedBy:   e.FirstString("managedBy"),
		SID:         sid,
	}, nil
}

func (g *groupDirectory) Create(ctx context.Context, spec adcore.GroupSpec) (*adcore.Group, error) {
	const op = "Group.Create"
	if err := spec.Validate(op, true); err != nil {
		return nil, err
	}

	dn := cnRDN(spec.Name) + "," + spec.Container
	add := []conn.Attribute{
		{Type: "objectClass", Vals: [][]byte{[]byte("top"), []byte("group")}},
		{Type: "cn", Vals: [][]byte{[]byte(spec.Name)}},
		{Type: "sAMAccountName", Vals: [][]byte{[]byte(spec.SamAccountName)}},
		{Type: "groupType", Vals: [][]byte{
			[]byte(attrs.GroupTypeString(attrs.GroupTypeValue(spec.Scope, spec.Category))),
		}},
	}
	if spec.Description != nil && *spec.Description != "" {
		add = append(add, conn.Attribute{Type: "description", Vals: [][]byte{[]byte(*spec.Description)}})
	}
	if spec.ManagedBy != nil && *spec.ManagedBy != "" {
		add = append(add, conn.Attribute{Type: "managedBy", Vals: [][]byte{[]byte(*spec.ManagedBy)}})
	}

	if err := g.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Add(ctx, dn, add)
	}); err != nil {
		return nil, g.c.annotateAlreadyExists(ctx, err, dn, deletedFilter("group", spec.Name, spec.Container))
	}

	created, err := g.Get(ctx, adcore.ByDN(dn))
	if err != nil {
		return nil, err
	}
	return created, g.c.replicate(ctx, created.GUID)
}

func (g *groupDirectory) Get(ctx context.Context, id adcore.Identity) (*adcore.Group, error) {
	e, err := g.c.getOne(ctx, "Group.Get", id, "group", groupAttrs)
	if err != nil {
		return nil, err
	}
	m, err := g.model(e)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindTransport, Op: "Group.Get", Err: err}
	}
	return m, nil
}

func (g *groupDirectory) Search(ctx context.Context, q adcore.Query) ([]adcore.Group, error) {
	const op = "Group.Search"
	entries, err := g.c.searchEntries(ctx, op, q, "group", groupAttrs)
	if err != nil {
		return nil, err
	}
	out := make([]adcore.Group, 0, len(entries))
	for _, e := range entries {
		m, err := g.model(e)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}
		out = append(out, *m)
	}
	return out, nil
}

func (g *groupDirectory) Update(ctx context.Context, id adcore.Identity, spec adcore.GroupSpec) (*adcore.Group, error) {
	const op = "Group.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := g.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := g.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var mods []conn.Modification
	if spec.SamAccountName != "" && spec.SamAccountName != current.SamAccountName {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "sAMAccountName",
			Vals: [][]byte{[]byte(spec.SamAccountName)},
		})
	}
	mods = appendStringMod(mods, "description", spec.Description, current.Description)
	mods = appendStringMod(mods, "managedBy", spec.ManagedBy, current.ManagedBy)

	// groupType is written whole, from both halves. Scope and category share
	// the field, so setting one half's bits without the other's would flip
	// the other — a scope change turning a security group into a distribution
	// group, silently.
	scope, category := spec.Scope, spec.Category
	if scope == "" {
		scope = current.Scope
	}
	if category == "" {
		category = current.Category
	}
	if scope != current.Scope || category != current.Category {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "groupType",
			Vals: [][]byte{[]byte(attrs.GroupTypeString(attrs.GroupTypeValue(scope, category)))},
		})
	}

	if len(mods) > 0 {
		if err := g.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.Modify(ctx, current.DN, mods)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	sameContainer, err := adcore.EqualFoldDN(spec.Container, current.Container)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	if spec.Name != current.Name || !sameContainer {
		superior := ""
		if !sameContainer {
			superior = spec.Container
		}
		if err := g.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.ModifyDN(ctx, current.DN, cnRDN(spec.Name), true, superior)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	updated, err := g.Get(ctx, adcore.ByGUID(current.GUID))
	if err != nil {
		return nil, err
	}
	return updated, g.c.replicate(ctx, updated.GUID)
}

func (g *groupDirectory) Delete(ctx context.Context, id adcore.Identity) error {
	const op = "Group.Delete"

	unlock := g.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := g.Get(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if err := g.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Delete(ctx, current.DN)
	}); err != nil {
		return adcore.WithIdentity(err, op, id)
	}

	_, err = g.Get(ctx, adcore.ByGUID(current.GUID))
	if isNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return &adcore.Error{
		Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Target: current.DN,
		Err: fmt.Errorf("the delete returned success but the object is still readable"),
	}
}

// appendStringMod encodes one tri-state string field: nil leaves it alone, a
// pointer to "" clears it (AD has no empty attribute value), anything else
// replaces it.
func appendStringMod(mods []conn.Modification, attr string, want *string, current string) []conn.Modification {
	if want == nil || *want == current {
		return mods
	}
	if *want == "" {
		return append(mods, conn.Modification{Op: conn.ModDelete, Type: attr})
	}
	return append(mods, conn.Modification{Op: conn.ModReplace, Type: attr, Vals: [][]byte{[]byte(*want)}})
}
