package adldap

import (
	"context"
	"errors"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/secdesc"
)

// ouAttrs is the projection an OU read requests: only what is in scope, never
// "*". Asking for everything pulls back attributes the model does not carry
// and makes a read's cost unbounded.
var ouAttrs = []string{"objectGUID", "distinguishedName", "name", "description", "nTSecurityDescriptor"}

// sdDACL scopes every read and write of nTSecurityDescriptor to the DACL.
// Without it a read also asks for the SACL, which needs a privilege the
// service account does not have, and a write would replace the owner with
// nothing.
func sdDACL() conn.Control { return conn.SDFlagsControl(conn.SDFlagDACL) }

type ouDirectory struct{ c *core }

var _ adcore.OUDirectory = (*ouDirectory)(nil)

// ouRDN builds the RDN for an OU, escaping the name per RFC 4514. Building it
// by concatenation is correct right up to the first name containing a comma,
// at which point the name silently reparents the object.
func ouRDN(name string) string { return "OU=" + adcore.EscapeValue(name) }

func (o *ouDirectory) model(e conn.Entry) (*adcore.OU, error) {
	guid, err := attrs.GUIDToString(e.First("objectGUID"))
	if err != nil {
		return nil, err
	}
	container, err := adcore.ContainerOf(e.DN)
	if err != nil {
		return nil, err
	}
	// A caller that could not read the descriptor sees Protected false rather
	// than an error: the rest of the model is still accurate, and a read that
	// fails wholesale over one unreadable attribute is worse than a narrow
	// gap. Writing it does fail loudly — see setProtection.
	protected := false
	if sd := e.First("nTSecurityDescriptor"); len(sd) > 0 {
		if protected, err = secdesc.IsProtected(sd); err != nil {
			return nil, err
		}
	}

	return &adcore.OU{
		GUID:        guid,
		DN:          e.DN,
		Name:        e.FirstString("name"),
		Container:   container,
		Description: e.FirstString("description"),
		Protected:   protected,
	}, nil
}

// setProtection writes the accidental-deletion Deny ACE, or lifts it.
//
// It is a read-modify-write of nTSecurityDescriptor rather than a blind
// replace: the descriptor carries every delegation on the object, so writing
// one built from scratch would discard them. secdesc treats entries it did not
// write as opaque bytes for that reason.
//
// The write is skipped when the object is already in the requested state,
// because a no-op replace of nTSecurityDescriptor still generates replication.
func (o *ouDirectory) setProtection(ctx context.Context, op, dn string, want bool) error {
	var current []byte
	if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: dn, Scope: conn.ScopeBase, Filter: "(objectClass=*)",
			Attributes: []string{"nTSecurityDescriptor"}, SizeLimit: 1,
			Controls: []conn.Control{sdDACL()},
		})
		if err != nil {
			return err
		}
		if len(res.Entries) == 0 {
			return fmt.Errorf("the object disappeared while setting protection")
		}
		current = res.Entries[0].First("nTSecurityDescriptor")
		return nil
	}); err != nil {
		return err
	}
	if len(current) == 0 {
		return &adcore.Error{
			Kind: adcore.KindDenied, Op: op, Target: dn,
			Err: errors.New("the directory returned no nTSecurityDescriptor; the account " +
				"cannot read the object's security descriptor, so protection cannot be managed"),
		}
	}

	updated, changed, err := secdesc.SetProtected(current, want)
	if err != nil {
		return &adcore.Error{Kind: adcore.KindTransport, Op: op, Target: dn, Err: err}
	}
	if !changed {
		return nil
	}
	return o.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Modify(ctx, dn, []conn.Modification{{
			Op: conn.ModReplace, Type: "nTSecurityDescriptor", Vals: [][]byte{updated},
		}}, sdDACL())
	})
}

func (o *ouDirectory) Create(ctx context.Context, spec adcore.OUSpec) (*adcore.OU, error) {
	const op = "OU.Create"
	if err := adcore.ValidateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := adcore.ValidateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	dn := ouRDN(spec.Name) + "," + spec.Container
	add := []conn.Attribute{
		{Type: "objectClass", Vals: [][]byte{[]byte("top"), []byte("organizationalUnit")}},
		{Type: "ou", Vals: [][]byte{[]byte(spec.Name)}},
	}
	if spec.Description != nil && *spec.Description != "" {
		add = append(add, conn.Attribute{Type: "description", Vals: [][]byte{[]byte(*spec.Description)}})
	}

	if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Add(ctx, dn, add)
	}); err != nil {
		return nil, o.c.annotateAlreadyExists(ctx, err, dn, deletedFilter("organizationalUnit", spec.Name, spec.Container))
	}

	// Protection is a second operation: AD has no way to create an object with
	// a Deny ACE already on it.
	if spec.Protected != nil && *spec.Protected {
		if err := o.setProtection(ctx, op, dn, true); err != nil {
			return nil, err
		}
	}

	// Read back through the same path Get uses, so an inconsistent result
	// after apply is impossible by construction.
	created, err := o.Get(ctx, adcore.ByDN(dn))
	if err != nil {
		return nil, err
	}
	return created, o.c.replicate(ctx, created.GUID)
}

func (o *ouDirectory) Get(ctx context.Context, id adcore.Identity) (*adcore.OU, error) {
	e, err := o.c.getOne(ctx, "OU.Get", id, "organizationalUnit", ouAttrs, sdDACL())
	if err != nil {
		return nil, err
	}
	m, err := o.model(e)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindTransport, Op: "OU.Get", Err: err}
	}
	return m, nil
}

func (o *ouDirectory) Search(ctx context.Context, q adcore.Query) ([]adcore.OU, error) {
	const op = "OU.Search"
	entries, err := o.c.searchEntries(ctx, op, q, "organizationalUnit", ouAttrs, sdDACL())
	if err != nil {
		return nil, err
	}
	out := make([]adcore.OU, 0, len(entries))
	for _, e := range entries {
		m, err := o.model(e)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}
		out = append(out, *m)
	}
	return out, nil
}

// Update writes the attribute delta and then, if the name or container
// changed, issues one ModifyDN.
//
// LDAP's ModifyDN performs the rename and the move together, which is why this
// carries none of the ordering care the cmdlet path needs: there is no window
// in which the object has a new name at its old parent, and no separate
// unprotect-before-move step, because there is only one operation.
func (o *ouDirectory) Update(ctx context.Context, id adcore.Identity, spec adcore.OUSpec) (*adcore.OU, error) {
	const op = "OU.Update"
	if err := adcore.ValidateName(op, spec.Name); err != nil {
		return nil, err
	}
	if err := adcore.ValidateContainer(op, spec.Container); err != nil {
		return nil, err
	}

	unlock := o.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := o.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var mods []conn.Modification
	if spec.Description != nil && *spec.Description != current.Description {
		if *spec.Description == "" {
			mods = append(mods, conn.Modification{Op: conn.ModDelete, Type: "description"})
		} else {
			mods = append(mods, conn.Modification{
				Op: conn.ModReplace, Type: "description",
				Vals: [][]byte{[]byte(*spec.Description)},
			})
		}
	}
	if len(mods) > 0 {
		if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.Modify(ctx, current.DN, mods)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	// Protection is lifted before a move and restored after. The Deny covers
	// DeleteTree, which AD checks on a ModifyDN that changes the parent, so a
	// protected OU cannot be moved while it is protected.
	wantProtected := current.Protected
	if spec.Protected != nil {
		wantProtected = *spec.Protected
	}

	sameContainer, err := adcore.EqualFoldDN(spec.Container, current.Container)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	moving := spec.Name != current.Name || !sameContainer
	if moving && current.Protected {
		if err := o.setProtection(ctx, op, current.DN, false); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}
	if moving {
		superior := ""
		if !sameContainer {
			superior = spec.Container
		}
		if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.ModifyDN(ctx, current.DN, ouRDN(spec.Name), true, superior)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	updated, err := o.Get(ctx, adcore.ByGUID(current.GUID))
	if err != nil {
		return nil, err
	}
	if updated.Protected != wantProtected {
		if err := o.setProtection(ctx, op, updated.DN, wantProtected); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
		if updated, err = o.Get(ctx, adcore.ByGUID(current.GUID)); err != nil {
			return nil, err
		}
	}
	return updated, o.c.replicate(ctx, updated.GUID)
}

// Delete removes an OU and returns nil only after a re-read confirms it is
// gone. A non-empty OU is never deleted recursively: the error names the child
// count. LDAP has no recursive delete without the tree-delete control, and
// that control is deliberately not reachable from this API.
func (o *ouDirectory) Delete(ctx context.Context, id adcore.Identity, opts adcore.DeleteOptions) error {
	const op = "OU.Delete"

	unlock := o.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := o.Get(ctx, id)
	if err != nil {
		// A not-found during Delete is success: the desired state holds.
		if isNotFound(err) {
			return nil
		}
		return err
	}

	// Unprotect is explicit at the call site because it is the destructive
	// half: without it, deleting an OU created with AD's own default fails.
	if opts.Unprotect && current.Protected {
		if err := o.setProtection(ctx, op, current.DN, false); err != nil {
			return adcore.WithIdentity(err, op, id)
		}
	}

	var children int
	if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: current.DN, Scope: conn.ScopeOneLevel,
			Filter: "(objectClass=*)", Attributes: []string{"distinguishedName"}, SizeLimit: 1,
		})
		if err != nil {
			return err
		}
		children = len(res.Entries)
		return nil
	}); err != nil {
		// A search that stopped at the size limit still proves a child
		// exists, which is all this probe asks.
		var e *adcore.Error
		if !asError(err, &e) || e.Kind != adcore.KindTooManyResults {
			return adcore.WithIdentity(err, op, id)
		}
		children = 1
	}
	if children > 0 {
		return &adcore.Error{
			Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Target: current.DN,
			Err: fmt.Errorf("organizational unit has %d child object(s); delete or move them first "+
				"(recursive deletion is deliberately not offered)", children),
		}
	}

	if err := o.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Delete(ctx, current.DN)
	}); err != nil {
		return adcore.WithIdentity(err, op, id)
	}

	_, err = o.Get(ctx, adcore.ByGUID(current.GUID))
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
