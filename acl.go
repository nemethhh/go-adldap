package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/secdesc"
)

type aclDirectory struct{ c *core }

var _ adcore.ACLDirectory = (*aclDirectory)(nil)

var aclAttrs = []string{"objectGUID", "distinguishedName", "nTSecurityDescriptor"}

// zeroGUID is what AD stores for "no object type". It must never reach the
// model: go-adpwsh normalises it to "", so emitting it here would show as a
// diff on every ACE without an object type for anyone switching backends.
const zeroGUID = "00000000-0000-0000-0000-000000000000"

func guidOrEmpty(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	s, err := attrs.GUIDToString(raw)
	if err != nil || s == zeroGUID {
		return ""
	}
	return s
}

// readDescriptor fetches nTSecurityDescriptor with the SD-flags control.
//
// An empty value is an error, never an empty ACL. AD returns the attribute
// empty rather than refusing when the caller cannot read the part asked for,
// and an empty ACL reads as "this object has no delegations" — which makes
// Terraform plan to create every one of them, and makes a Revoke a silent
// no-op.
func (a *aclDirectory) readDescriptor(ctx context.Context, op string, id adcore.Identity) (conn.Entry, []byte, error) {
	e, err := a.c.getOne(ctx, op, id, "*", aclAttrs, sdDACL())
	if err != nil {
		return conn.Entry{}, nil, err
	}
	sd := e.First("nTSecurityDescriptor")
	if len(sd) == 0 {
		return conn.Entry{}, nil, &adcore.Error{
			Kind: adcore.KindDenied, Op: op, Identity: id.String(), Target: e.DN,
			Err: fmt.Errorf("nTSecurityDescriptor read back empty; the account this client " +
				"binds as cannot read the object's security descriptor"),
		}
	}
	return e, sd, nil
}

func (a *aclDirectory) Get(ctx context.Context, id adcore.Identity) ([]adcore.ACE, error) {
	const op = "ACL.Get"
	_, sd, err := a.readDescriptor(ctx, op, id)
	if err != nil {
		return nil, err
	}
	decoded, err := secdesc.DecodeACEs(sd)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Err: err}
	}
	out := make([]adcore.ACE, 0, len(decoded))
	for _, d := range decoded {
		sid, err := attrs.SIDToString(d.TrusteeSID)
		if err != nil {
			// A trustee that will not format is a corrupt entry, not a reason
			// to fail the whole read: the remaining ACEs are still accurate
			// and the user needs to see them to fix this one.
			continue
		}
		t := adcore.ACEAllow
		if d.Deny {
			t = adcore.ACEDeny
		}
		out = append(out, adcore.ACE{
			Trustee:             sid,
			Type:                t,
			Rights:              secdesc.RightsNames(d.Mask),
			ObjectType:          guidOrEmpty(d.ObjectType),
			InheritedObjectType: guidOrEmpty(d.InheritedObjectType),
			Inheritance:         secdesc.InheritanceOf(d.Flags),
			Inherited:           d.Inherited,
		})
	}
	return out, nil
}

// decode turns the contract's ACE into the binary form secdesc works in.
// Every failure here names the offending value: an ACE the caller cannot see
// the shape of is a permission they believe they granted.
func (a *aclDirectory) decode(op string, ace adcore.ACE) (secdesc.DecodedACE, error) {
	sid, err := attrs.SIDFromString(ace.Trustee)
	if err != nil {
		return secdesc.DecodedACE{}, &adcore.Error{Kind: adcore.KindConstraint, Op: op,
			Err: fmt.Errorf("trustee %q is not a SID: %w", ace.Trustee, err)}
	}
	mask, err := secdesc.RightsMask(ace.Rights)
	if err != nil {
		return secdesc.DecodedACE{}, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	var ot, iot []byte
	if ace.ObjectType != "" {
		if ot, err = attrs.GUIDToBytes(ace.ObjectType); err != nil {
			return secdesc.DecodedACE{}, &adcore.Error{Kind: adcore.KindConstraint, Op: op,
				Err: fmt.Errorf("object type %q is not a GUID: %w", ace.ObjectType, err)}
		}
	}
	if ace.InheritedObjectType != "" {
		if iot, err = attrs.GUIDToBytes(ace.InheritedObjectType); err != nil {
			return secdesc.DecodedACE{}, &adcore.Error{Kind: adcore.KindConstraint, Op: op,
				Err: fmt.Errorf("inherited object type %q is not a GUID: %w", ace.InheritedObjectType, err)}
		}
	}
	return secdesc.DecodedACE{
		TrusteeSID:          sid,
		Deny:                ace.Type == adcore.ACEDeny,
		Mask:                mask,
		ObjectType:          ot,
		InheritedObjectType: iot,
		Flags:               secdesc.FlagsFor(ace.Inheritance),
	}, nil
}

// write replaces nTSecurityDescriptor, with the SD-flags control scoping it to
// the DACL. Without the control the write replaces the owner as well, and the
// bound account is rarely the owner.
func (a *aclDirectory) write(ctx context.Context, op, dn string, sd []byte) error {
	return a.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Modify(ctx, dn, []conn.Modification{{
			Op: conn.ModReplace, Type: "nTSecurityDescriptor", Vals: [][]byte{sd},
		}}, sdDACL())
	})
}

// keyOf is the canonical key for a decoded entry. Grant, Revoke and drift
// detection all compare on adcore.CanonicalACEKey; a second notion of ACE
// equality anywhere here is how a resource adds a duplicate on every apply
// while reporting no change.
func keyOf(d secdesc.DecodedACE) (string, bool) {
	sid, err := attrs.SIDToString(d.TrusteeSID)
	if err != nil {
		return "", false
	}
	t := adcore.ACEAllow
	if d.Deny {
		t = adcore.ACEDeny
	}
	return adcore.CanonicalACEKey(adcore.ACE{
		Trustee:             sid,
		Type:                t,
		Rights:              secdesc.RightsNames(d.Mask),
		ObjectType:          guidOrEmpty(d.ObjectType),
		InheritedObjectType: guidOrEmpty(d.InheritedObjectType),
		Inheritance:         secdesc.InheritanceOf(d.Flags),
	}), true
}

// Grant adds ACEs that are not already there.
//
// Idempotence is on adcore.CanonicalACEKey, the same key drift detection
// compares on. Using a different notion of equality here is how a resource
// ends up adding a duplicate on every apply while reporting no change.
func (a *aclDirectory) Grant(ctx context.Context, id adcore.Identity, list []adcore.ACE) error {
	const op = "ACL.Grant"
	if len(list) == 0 {
		return nil
	}

	unlock := a.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	e, sd, err := a.readDescriptor(ctx, op, id)
	if err != nil {
		return err
	}
	existing, err := a.Get(ctx, adcore.ByDN(e.DN))
	if err != nil {
		return err
	}
	have := make(map[string]struct{}, len(existing))
	for _, x := range existing {
		if !x.Inherited {
			have[adcore.CanonicalACEKey(x)] = struct{}{}
		}
	}

	var add []secdesc.DecodedACE
	for _, ace := range list {
		if _, ok := have[adcore.CanonicalACEKey(ace)]; ok {
			continue
		}
		d, err := a.decode(op, ace)
		if err != nil {
			return adcore.WithIdentity(err, op, id)
		}
		add = append(add, d)
	}

	updated, changed, err := secdesc.AddACEs(sd, add)
	if err != nil {
		return &adcore.Error{Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Err: err}
	}
	if !changed {
		return nil
	}
	if err := a.write(ctx, op, e.DN, updated); err != nil {
		return adcore.WithIdentity(err, op, id)
	}
	return nil
}

// Revoke removes the ACEs named, matching on the canonical key so that the
// order and case the caller wrote the rights in do not matter.
//
// Revoking something absent is not an error and writes nothing: Terraform
// destroys resources whose ACE a person has already removed by hand, and
// failing there strands the state.
func (a *aclDirectory) Revoke(ctx context.Context, id adcore.Identity, list []adcore.ACE) error {
	const op = "ACL.Revoke"
	if len(list) == 0 {
		return nil
	}

	unlock := a.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	e, sd, err := a.readDescriptor(ctx, op, id)
	if err != nil {
		return err
	}

	drop := make(map[string]struct{}, len(list))
	for _, ace := range list {
		// Decoding first validates the rights and GUIDs, so a revoke naming a
		// right that does not exist fails the same way a grant does rather
		// than silently matching nothing.
		if _, err := a.decode(op, ace); err != nil {
			return adcore.WithIdentity(err, op, id)
		}
		drop[adcore.CanonicalACEKey(ace)] = struct{}{}
	}

	updated, changed, err := secdesc.RemoveACEs(sd, func(d secdesc.DecodedACE) bool {
		key, ok := keyOf(d)
		if !ok {
			return false
		}
		_, drops := drop[key]
		return drops
	})
	if err != nil {
		return &adcore.Error{Kind: adcore.KindConstraint, Op: op, Identity: id.String(), Err: err}
	}
	if !changed {
		return nil
	}
	if err := a.write(ctx, op, e.DN, updated); err != nil {
		return adcore.WithIdentity(err, op, id)
	}
	return nil
}
