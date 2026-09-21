package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

const gmsaClass = "msDS-GroupManagedServiceAccount"

var gmsaAttrs = []string{
	"objectGUID", "distinguishedName", "name", "sAMAccountName", "objectSid",
	"dNSHostName", "description", "displayName", "userAccountControl",
	"servicePrincipalName", "msDS-GroupMSAMembership",
	"msDS-SupportedEncryptionTypes", "msDS-ManagedPasswordInterval",
	"accountExpires",
}

type serviceAccountDirectory struct{ c *core }

var _ adcore.ServiceAccountDirectory = (*serviceAccountDirectory)(nil)

func (s *serviceAccountDirectory) model(e conn.Entry) (*adcore.GMSA, error) {
	guid, err := attrs.GUIDToString(e.First("objectGUID"))
	if err != nil {
		return nil, err
	}
	container, err := adcore.ContainerOf(e.DN)
	if err != nil {
		return nil, err
	}
	var uac uint32
	if raw := e.FirstString("userAccountControl"); raw != "" {
		if uac, err = attrs.ParseUint32(raw); err != nil {
			return nil, err
		}
	}
	expires, err := attrs.FileTimeToTime(e.FirstString("accountExpires"))
	if err != nil {
		return nil, err
	}
	var enc uint32
	if raw := e.FirstString("msDS-SupportedEncryptionTypes"); raw != "" {
		if enc, err = attrs.ParseUint32(raw); err != nil {
			return nil, err
		}
	}
	interval := 0
	if raw := e.FirstString("msDS-ManagedPasswordInterval"); raw != "" {
		v, err := attrs.ParseUint32(raw)
		if err != nil {
			return nil, err
		}
		interval = int(v)
	}

	return &adcore.GMSA{
		GUID: guid, DN: e.DN, Name: e.FirstString("name"),
		SamAccountName:                samWithoutDollar(e.FirstString("sAMAccountName")),
		Container:                     container,
		SID:                           mustSID(e),
		DNSHostName:                   e.FirstString("dNSHostName"),
		Description:                   e.FirstString("description"),
		DisplayName:                   e.FirstString("displayName"),
		Enabled:                       uac&attrs.UACAccountDisable == 0,
		TrustedForDelegation:          uac&attrs.UACTrustedForDelegation != 0,
		ServicePrincipalNames:         strValues(e, "servicePrincipalName"),
		KerberosEncryptionType:        attrs.EncTypeNames(enc),
		ManagedPasswordIntervalInDays: interval,
		AccountExpiration:             expires,
	}, nil
}

func (s *serviceAccountDirectory) Create(ctx context.Context, spec adcore.GMSASpec) (*adcore.GMSA, error) {
	const op = "ServiceAccount.Create"
	if err := spec.Validate(op, true); err != nil {
		return nil, err
	}
	dn := cnRDN(spec.Name) + "," + spec.Container

	uac := attrs.UACWorkstationTrustAccount
	if spec.Enabled != nil && !*spec.Enabled {
		uac |= attrs.UACAccountDisable
	}
	if spec.TrustedForDelegation != nil && *spec.TrustedForDelegation {
		uac |= attrs.UACTrustedForDelegation
	}

	// AD refuses a gMSA with no msDS-GroupMSAMembership, so the attribute is
	// written unconditionally. spec.PrincipalsAllowed being nil means "nobody",
	// which is an empty but present DACL — not an absent attribute.
	membership, err := s.c.principalSDValue(ctx, op, spec.PrincipalsAllowed)
	if err != nil {
		return nil, err
	}

	add := []conn.Attribute{
		{Type: "objectClass", Vals: [][]byte{
			[]byte("top"), []byte("person"), []byte("organizationalPerson"),
			[]byte("user"), []byte("computer"), []byte(gmsaClass),
		}},
		{Type: "cn", Vals: [][]byte{[]byte(spec.Name)}},
		{Type: "sAMAccountName", Vals: [][]byte{[]byte(samWithDollar(spec.SamAccountName))}},
		{Type: "userAccountControl", Vals: [][]byte{[]byte(attrs.Uint32String(uac))}},
		{Type: "dNSHostName", Vals: [][]byte{[]byte(*spec.DNSHostName)}},
		{Type: "msDS-GroupMSAMembership", Vals: [][]byte{membership}},
	}
	for _, f := range []struct {
		attr string
		val  *string
	}{
		{"description", spec.Description},
		{"displayName", spec.DisplayName},
	} {
		if f.val != nil && *f.val != "" {
			add = append(add, conn.Attribute{Type: f.attr, Vals: [][]byte{[]byte(*f.val)}})
		}
	}
	if spec.ServicePrincipalNames != nil && len(*spec.ServicePrincipalNames) > 0 {
		add = append(add, conn.Attribute{Type: "servicePrincipalName", Vals: byteValues(*spec.ServicePrincipalNames)})
	}
	if spec.KerberosEncryptionType != nil {
		add = append(add, conn.Attribute{Type: "msDS-SupportedEncryptionTypes",
			Vals: [][]byte{[]byte(attrs.Uint32String(attrs.EncTypeBits(*spec.KerberosEncryptionType)))}})
	}
	// Create-only. Sending it on an Update is refused by AD, which is why it
	// appears here and nowhere else.
	if spec.ManagedPasswordIntervalInDays != nil {
		add = append(add, conn.Attribute{Type: "msDS-ManagedPasswordInterval",
			Vals: [][]byte{[]byte(fmt.Sprintf("%d", *spec.ManagedPasswordIntervalInDays))}})
	}
	if spec.AccountExpiration.IsSet() {
		add = append(add, conn.Attribute{Type: "accountExpires",
			Vals: [][]byte{[]byte(attrs.TimeToFileTime(spec.AccountExpiration.Value()))}})
	}

	if err := s.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Add(ctx, dn, add)
	}); err != nil {
		return nil, s.c.annotateAlreadyExists(ctx, err, deletedFilter(gmsaClass, spec.Name, spec.Container))
	}

	created, err := s.Get(ctx, adcore.ByDN(dn))
	if err != nil {
		return nil, err
	}
	return created, s.c.replicate(ctx, created.GUID)
}

func (s *serviceAccountDirectory) Get(ctx context.Context, id adcore.Identity) (*adcore.GMSA, error) {
	const op = "ServiceAccount.Get"
	e, err := s.c.getOne(ctx, op, id, gmsaClass, gmsaAttrs)
	if err != nil {
		return nil, err
	}
	m, err := s.model(e)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
	}
	if raw := e.First("msDS-GroupMSAMembership"); len(raw) > 0 {
		if m.PrincipalsAllowed, err = s.c.principalGUIDs(ctx, op, raw); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (s *serviceAccountDirectory) Search(ctx context.Context, q adcore.Query) ([]adcore.GMSA, error) {
	const op = "ServiceAccount.Search"
	entries, err := s.c.searchEntries(ctx, op, q, gmsaClass, gmsaAttrs)
	if err != nil {
		return nil, err
	}
	out := make([]adcore.GMSA, 0, len(entries))
	for _, e := range entries {
		m, err := s.model(e)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}
		if raw := e.First("msDS-GroupMSAMembership"); len(raw) > 0 {
			if m.PrincipalsAllowed, err = s.c.principalGUIDs(ctx, op, raw); err != nil {
				return nil, err
			}
		}
		out = append(out, *m)
	}
	return out, nil
}

func (s *serviceAccountDirectory) Update(ctx context.Context, id adcore.Identity, spec adcore.GMSASpec) (*adcore.GMSA, error) {
	const op = "ServiceAccount.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := s.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var mods []conn.Modification
	if spec.SamAccountName != "" && spec.SamAccountName != current.SamAccountName {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "sAMAccountName",
			Vals: [][]byte{[]byte(samWithDollar(spec.SamAccountName))},
		})
	}
	mods = appendStringMod(mods, "dNSHostName", spec.DNSHostName, current.DNSHostName)
	mods = appendStringMod(mods, "description", spec.Description, current.Description)
	mods = appendStringMod(mods, "displayName", spec.DisplayName, current.DisplayName)
	if spec.ServicePrincipalNames != nil {
		mods = replaceMulti(mods, "servicePrincipalName", *spec.ServicePrincipalNames)
	}
	if spec.KerberosEncryptionType != nil {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "msDS-SupportedEncryptionTypes",
			Vals: [][]byte{[]byte(attrs.Uint32String(attrs.EncTypeBits(*spec.KerberosEncryptionType)))},
		})
	}
	if spec.PrincipalsAllowed != nil {
		sd, err := s.c.principalSDValue(ctx, op, spec.PrincipalsAllowed)
		if err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "msDS-GroupMSAMembership", Vals: [][]byte{sd},
		})
	}

	currentUAC := attrs.UACWorkstationTrustAccount
	if !current.Enabled {
		currentUAC |= attrs.UACAccountDisable
	}
	if current.TrustedForDelegation {
		currentUAC |= attrs.UACTrustedForDelegation
	}
	wantUAC := currentUAC
	if spec.Enabled != nil {
		if *spec.Enabled {
			wantUAC &^= attrs.UACAccountDisable
		} else {
			wantUAC |= attrs.UACAccountDisable
		}
	}
	if spec.TrustedForDelegation != nil {
		if *spec.TrustedForDelegation {
			wantUAC |= attrs.UACTrustedForDelegation
		} else {
			wantUAC &^= attrs.UACTrustedForDelegation
		}
	}
	if wantUAC != currentUAC {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "userAccountControl",
			Vals: [][]byte{[]byte(attrs.Uint32String(wantUAC))},
		})
	}

	switch {
	case spec.AccountExpiration.IsSet():
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "accountExpires",
			Vals: [][]byte{[]byte(attrs.TimeToFileTime(spec.AccountExpiration.Value()))},
		})
	case spec.AccountExpiration.IsClear():
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "accountExpires", Vals: [][]byte{[]byte("0")},
		})
	}

	// msDS-ManagedPasswordInterval is deliberately absent: it is create-only,
	// AD refuses a modify of it, and GMSASpec documents that Update ignores it.

	if len(mods) > 0 {
		if err := s.c.withConn(ctx, op, func(cn conn.Conn) error {
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
		if err := s.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.ModifyDN(ctx, current.DN, cnRDN(spec.Name), true, superior)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	updated, err := s.Get(ctx, adcore.ByGUID(current.GUID))
	if err != nil {
		return nil, err
	}
	return updated, s.c.replicate(ctx, updated.GUID)
}

func (s *serviceAccountDirectory) Delete(ctx context.Context, id adcore.Identity) error {
	const op = "ServiceAccount.Delete"

	unlock := s.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := s.Get(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if err := s.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Delete(ctx, current.DN)
	}); err != nil {
		return adcore.WithIdentity(err, op, id)
	}

	_, err = s.Get(ctx, adcore.ByGUID(current.GUID))
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
