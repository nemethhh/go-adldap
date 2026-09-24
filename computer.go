package adldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

var computerAttrs = []string{
	"objectGUID", "distinguishedName", "name", "sAMAccountName", "objectSid",
	"dNSHostName", "description", "displayName", "location", "managedBy",
	"userAccountControl", "servicePrincipalName", "msDS-AllowedToDelegateTo",
	"msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-SupportedEncryptionTypes",
	"accountExpires", "operatingSystem", "operatingSystemVersion",
}

type computerDirectory struct{ c *core }

var _ adcore.ComputerDirectory = (*computerDirectory)(nil)

// samWithDollar is what AD stores. New-ADComputer appends the "$" itself, so
// the spec carries the unsuffixed name and this is the only place it is added.
// Appending unconditionally would produce "SRV01$$" for a caller who wrote the
// suffixed form, which AD accepts and which then reads back wrong forever.
func samWithDollar(s string) string {
	if strings.HasSuffix(s, "$") {
		return s
	}
	return s + "$"
}

// samWithoutDollar is the inverse, applied on every read. Without it the model
// carries "SRV01$" while configuration carries "SRV01", and Terraform reports
// an inconsistent result after apply on every single plan.
func samWithoutDollar(s string) string { return strings.TrimSuffix(s, "$") }

// strValues reads every value of a multi-valued textual attribute. It returns
// nil, not an empty slice, for an absent attribute: nil is what an unset
// multi-valued attribute means everywhere else in this package.
func strValues(e conn.Entry, attr string) []string {
	raw := e.Attrs[attr]
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, len(raw))
	for i, v := range raw {
		out[i] = string(v)
	}
	return out
}

// byteValues is the same for a slice of strings on the way out.
func byteValues(vals []string) [][]byte {
	out := make([][]byte, len(vals))
	for i, v := range vals {
		out[i] = []byte(v)
	}
	return out
}

// replaceMulti builds the full-replace modification a tri-state slice field
// means. An empty non-nil slice replaces with nothing, which is a Modify with
// no values — the LDAP spelling of "delete every value".
func replaceMulti(mods []conn.Modification, attr string, vals []string) []conn.Modification {
	return append(mods, conn.Modification{
		Op: conn.ModReplace, Type: attr, Vals: byteValues(vals),
	})
}

func (cd *computerDirectory) model(e conn.Entry) (*adcore.Computer, error) {
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

	return &adcore.Computer{
		GUID: guid, DN: e.DN, Name: e.FirstString("name"),
		SamAccountName:         samWithoutDollar(e.FirstString("sAMAccountName")),
		Container:              container,
		SID:                    mustSID(e),
		Enabled:                uac&attrs.UACAccountDisable == 0,
		DNSHostName:            e.FirstString("dNSHostName"),
		Description:            e.FirstString("description"),
		DisplayName:            e.FirstString("displayName"),
		Location:               e.FirstString("location"),
		ManagedBy:              e.FirstString("managedBy"),
		TrustedForDelegation:   uac&attrs.UACTrustedForDelegation != 0,
		ServicePrincipalNames:  strValues(e, "servicePrincipalName"),
		AllowedToDelegateTo:    strValues(e, "msDS-AllowedToDelegateTo"),
		KerberosEncryptionType: attrs.EncTypeNames(enc),
		AccountExpiration:      expires,
		OperatingSystem:        e.FirstString("operatingSystem"),
		OperatingSystemVersion: e.FirstString("operatingSystemVersion"),
	}, nil
}

func (cd *computerDirectory) Create(ctx context.Context, spec adcore.ComputerSpec) (*adcore.Computer, error) {
	const op = "Computer.Create"
	if err := spec.Validate(op, true); err != nil {
		return nil, err
	}
	dn := cnRDN(spec.Name) + "," + spec.Container

	// WORKSTATION_TRUST_ACCOUNT, not NORMAL_ACCOUNT. A computer created with
	// the user bit reads back perfectly and is an object AD will never
	// authenticate, so nothing downstream notices the mistake.
	uac := attrs.UACWorkstationTrustAccount
	if spec.Enabled != nil && !*spec.Enabled {
		uac |= attrs.UACAccountDisable
	}
	if spec.TrustedForDelegation != nil && *spec.TrustedForDelegation {
		uac |= attrs.UACTrustedForDelegation
	}

	add := []conn.Attribute{
		{Type: "objectClass", Vals: [][]byte{
			[]byte("top"), []byte("person"), []byte("organizationalPerson"),
			[]byte("user"), []byte("computer"),
		}},
		{Type: "cn", Vals: [][]byte{[]byte(spec.Name)}},
		{Type: "sAMAccountName", Vals: [][]byte{[]byte(samWithDollar(spec.SamAccountName))}},
		{Type: "userAccountControl", Vals: [][]byte{[]byte(attrs.Uint32String(uac))}},
	}
	for _, f := range []struct {
		attr string
		val  *string
	}{
		{"dNSHostName", spec.DNSHostName},
		{"description", spec.Description},
		{"displayName", spec.DisplayName},
		{"location", spec.Location},
		{"managedBy", spec.ManagedBy},
	} {
		if f.val != nil && *f.val != "" {
			add = append(add, conn.Attribute{Type: f.attr, Vals: [][]byte{[]byte(*f.val)}})
		}
	}
	if spec.ServicePrincipalNames != nil && len(*spec.ServicePrincipalNames) > 0 {
		add = append(add, conn.Attribute{Type: "servicePrincipalName", Vals: byteValues(*spec.ServicePrincipalNames)})
	}
	if spec.AllowedToDelegateTo != nil && len(*spec.AllowedToDelegateTo) > 0 {
		add = append(add, conn.Attribute{Type: "msDS-AllowedToDelegateTo", Vals: byteValues(*spec.AllowedToDelegateTo)})
	}
	if spec.KerberosEncryptionType != nil {
		add = append(add, conn.Attribute{Type: "msDS-SupportedEncryptionTypes",
			Vals: [][]byte{[]byte(attrs.Uint32String(attrs.EncTypeBits(*spec.KerberosEncryptionType)))}})
	}
	if spec.AccountExpiration.IsSet() {
		add = append(add, conn.Attribute{Type: "accountExpires",
			Vals: [][]byte{[]byte(attrs.TimeToFileTime(spec.AccountExpiration.Value()))}})
	}
	// This attribute takes no SD-flags control. It is an ordinary binary
	// attribute that happens to hold a descriptor; it is not
	// nTSecurityDescriptor, and sending the control with it is refused.
	if spec.PrincipalsAllowed != nil {
		sd, err := cd.c.principalSDValue(ctx, op, spec.PrincipalsAllowed)
		if err != nil {
			return nil, err
		}
		add = append(add, conn.Attribute{
			Type: "msDS-AllowedToActOnBehalfOfOtherIdentity", Vals: [][]byte{sd},
		})
	}

	if err := cd.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Add(ctx, dn, add)
	}); err != nil {
		return nil, cd.c.annotateAlreadyExists(ctx, err, dn, deletedFilter("computer", spec.Name, spec.Container))
	}

	created, err := cd.Get(ctx, adcore.ByDN(dn))
	if err != nil {
		return nil, err
	}
	return created, cd.c.replicate(ctx, created.GUID)
}

func (cd *computerDirectory) Get(ctx context.Context, id adcore.Identity) (*adcore.Computer, error) {
	const op = "Computer.Get"
	e, err := cd.c.getOne(ctx, op, id, "computer", computerAttrs, sdDACL())
	if err != nil {
		return nil, err
	}
	m, err := cd.model(e)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
	}
	if raw := e.First("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(raw) > 0 {
		if m.PrincipalsAllowed, err = cd.c.principalGUIDs(ctx, op, raw); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (cd *computerDirectory) Search(ctx context.Context, q adcore.Query) ([]adcore.Computer, error) {
	const op = "Computer.Search"
	entries, err := cd.c.searchEntries(ctx, op, q, "computer", computerAttrs, sdDACL())
	if err != nil {
		return nil, err
	}
	out := make([]adcore.Computer, 0, len(entries))
	for _, e := range entries {
		m, err := cd.model(e)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}
		if raw := e.First("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(raw) > 0 {
			if m.PrincipalsAllowed, err = cd.c.principalGUIDs(ctx, op, raw); err != nil {
				return nil, err
			}
		}
		out = append(out, *m)
	}
	return out, nil
}

func (cd *computerDirectory) Update(ctx context.Context, id adcore.Identity, spec adcore.ComputerSpec) (*adcore.Computer, error) {
	const op = "Computer.Update"
	if err := spec.Validate(op, false); err != nil {
		return nil, err
	}

	unlock := cd.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := cd.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var mods []conn.Modification
	// SamAccountName is compared against the unsuffixed model value. Comparing
	// it to the raw "SRV01$" AD stores would differ every time and rewrite the
	// attribute on every update.
	if spec.SamAccountName != "" && spec.SamAccountName != current.SamAccountName {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "sAMAccountName",
			Vals: [][]byte{[]byte(samWithDollar(spec.SamAccountName))},
		})
	}
	mods = appendStringMod(mods, "dNSHostName", spec.DNSHostName, current.DNSHostName)
	mods = appendStringMod(mods, "description", spec.Description, current.Description)
	mods = appendStringMod(mods, "displayName", spec.DisplayName, current.DisplayName)
	mods = appendStringMod(mods, "location", spec.Location, current.Location)
	mods = appendStringMod(mods, "managedBy", spec.ManagedBy, current.ManagedBy)

	if spec.ServicePrincipalNames != nil {
		mods = replaceMulti(mods, "servicePrincipalName", *spec.ServicePrincipalNames)
	}
	if spec.AllowedToDelegateTo != nil {
		mods = replaceMulti(mods, "msDS-AllowedToDelegateTo", *spec.AllowedToDelegateTo)
	}
	if spec.KerberosEncryptionType != nil {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "msDS-SupportedEncryptionTypes",
			Vals: [][]byte{[]byte(attrs.Uint32String(attrs.EncTypeBits(*spec.KerberosEncryptionType)))},
		})
	}

	// nil leaves RBCD alone; a non-nil slice, empty or not, replaces it. An
	// empty slice writes a present-but-empty DACL, which is "nobody may
	// impersonate here" — deleting the attribute instead would mean something
	// different.
	if spec.PrincipalsAllowed != nil {
		sd, err := cd.c.principalSDValue(ctx, op, spec.PrincipalsAllowed)
		if err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "msDS-AllowedToActOnBehalfOfOtherIdentity",
			Vals: [][]byte{sd},
		})
	}

	// The current value is rebuilt and only the named bits moved, the same way
	// applyUAC does for a user: a value computed from the spec alone would
	// clear every bit the spec does not mention.
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

	if len(mods) > 0 {
		if err := cd.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.Modify(ctx, current.DN, mods)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	// Rename and move are one ModifyDN, exactly as in userDirectory.Update.
	sameContainer, err := adcore.EqualFoldDN(spec.Container, current.Container)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	if spec.Name != current.Name || !sameContainer {
		superior := ""
		if !sameContainer {
			superior = spec.Container
		}
		if err := cd.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.ModifyDN(ctx, current.DN, cnRDN(spec.Name), true, superior)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	updated, err := cd.Get(ctx, adcore.ByGUID(current.GUID))
	if err != nil {
		return nil, err
	}
	return updated, cd.c.replicate(ctx, updated.GUID)
}

func (cd *computerDirectory) Delete(ctx context.Context, id adcore.Identity) error {
	const op = "Computer.Delete"

	unlock := cd.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := cd.Get(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if err := cd.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Delete(ctx, current.DN)
	}); err != nil {
		return adcore.WithIdentity(err, op, id)
	}

	// Delete returns nil only after a re-read confirms the object is gone.
	// This is the contract adcoretest.RunDirectorySuite asserts.
	_, err = cd.Get(ctx, adcore.ByGUID(current.GUID))
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
