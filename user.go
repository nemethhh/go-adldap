package adldap

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

var userAttrs = []string{
	"objectGUID", "distinguishedName", "name", "sAMAccountName",
	"userPrincipalName", "displayName", "givenName", "sn", "description",
	"userAccountControl", "objectSid", "pwdLastSet", "accountExpires",
}

type userDirectory struct{ c *core }

var _ adcore.UserDirectory = (*userDirectory)(nil)

// mustSID formats objectSid when present. An object read before the DC has
// stamped one is not an error.
func mustSID(e conn.Entry) string {
	raw := e.First("objectSid")
	if len(raw) == 0 {
		return ""
	}
	sid, err := attrs.SIDToString(raw)
	if err != nil {
		return ""
	}
	return sid
}

func (u *userDirectory) model(e conn.Entry) (*adcore.User, error) {
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

	return &adcore.User{
		GUID: guid, DN: e.DN, Name: e.FirstString("name"),
		SamAccountName:    e.FirstString("sAMAccountName"),
		UserPrincipalName: e.FirstString("userPrincipalName"),
		DisplayName:       e.FirstString("displayName"),
		GivenName:         e.FirstString("givenName"),
		Surname:           e.FirstString("sn"),
		Description:       e.FirstString("description"),
		Container:         container,
		// Stated positively, though AD's own bits are the negative form.
		Enabled:         uac&attrs.UACAccountDisable == 0,
		PasswordExpires: uac&attrs.UACDontExpirePassword == 0,
		// pwdLastSet == 0 means the user must change the password at next
		// logon. It is an interval attribute, not a timestamp, so it is only
		// ever compared against zero here.
		ChangePasswordAtLogon: e.FirstString("pwdLastSet") == "0",
		// CanChangePassword is an ACE pair; Phase 5 reads it. True is the AD
		// default for a new account.
		CanChangePassword: true,
		AccountExpiration: expires,
		SID:               mustSID(e),
	}, nil
}

// refuseUnimplemented rejects the spec fields backed by a security descriptor,
// which this backend cannot write yet. Silently ignoring them would leave
// Terraform reporting a state it never achieved.
func refuseUnimplemented(op string, spec adcore.UserSpec) error {
	if spec.CanChangePassword != nil && !*spec.CanChangePassword {
		return &adcore.Error{
			Kind: adcore.KindUnsupported, Op: op,
			Err: errors.New("can_change_password requires writing a security descriptor, " +
				"which this backend does not yet implement"),
		}
	}
	return nil
}

// applyUAC sets or clears only the bits the spec names and leaves the rest of
// userAccountControl alone. Writing a value computed from the spec alone would
// clear every bit the spec does not mention — enabling an account would turn
// password expiry back on.
func applyUAC(current uint32, spec adcore.UserSpec) uint32 {
	out := current
	if spec.Enabled != nil {
		if *spec.Enabled {
			out &^= attrs.UACAccountDisable
		} else {
			out |= attrs.UACAccountDisable
		}
	}
	if spec.PasswordExpires != nil {
		if *spec.PasswordExpires {
			out &^= attrs.UACDontExpirePassword
		} else {
			out |= attrs.UACDontExpirePassword
		}
	}
	return out
}

func (u *userDirectory) Create(ctx context.Context, spec adcore.UserSpec) (*adcore.User, error) {
	const op = "User.Create"
	if err := refuseUnimplemented(op, spec); err != nil {
		return nil, err
	}
	if err := spec.Validate(op); err != nil {
		return nil, err
	}

	name := spec.SamAccountName
	if spec.Name != nil && *spec.Name != "" {
		name = *spec.Name
	}
	dn := cnRDN(name) + "," + spec.Container

	// A new account starts disabled unless the spec says otherwise: AD
	// refuses to enable an account that has no password yet.
	uac := applyUAC(attrs.UACNormalAccount|attrs.UACAccountDisable, spec)

	add := []conn.Attribute{
		{Type: "objectClass", Vals: [][]byte{
			[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("user"),
		}},
		{Type: "cn", Vals: [][]byte{[]byte(name)}},
		{Type: "sAMAccountName", Vals: [][]byte{[]byte(spec.SamAccountName)}},
		{Type: "userAccountControl", Vals: [][]byte{[]byte(attrs.Uint32String(uac))}},
	}
	for _, f := range []struct {
		attr string
		val  *string
	}{
		{"userPrincipalName", spec.UserPrincipalName},
		{"displayName", spec.DisplayName},
		{"givenName", spec.GivenName},
		{"sn", spec.Surname},
		{"description", spec.Description},
	} {
		if f.val != nil && *f.val != "" {
			add = append(add, conn.Attribute{Type: f.attr, Vals: [][]byte{[]byte(*f.val)}})
		}
	}
	if spec.AccountExpiration.IsSet() {
		add = append(add, conn.Attribute{
			Type: "accountExpires",
			Vals: [][]byte{[]byte(attrs.TimeToFileTime(spec.AccountExpiration.Value()))},
		})
	}
	if spec.ChangePasswordAtLogon != nil && *spec.ChangePasswordAtLogon {
		add = append(add, conn.Attribute{Type: "pwdLastSet", Vals: [][]byte{[]byte("0")}})
	}

	if err := u.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Add(ctx, dn, add)
	}); err != nil {
		return nil, u.c.annotateAlreadyExists(ctx, err, deletedFilter("user", name, spec.Container))
	}

	if spec.Password != nil && !spec.Password.IsZero() {
		if err := u.SetPassword(ctx, adcore.ByDN(dn), *spec.Password); err != nil {
			return nil, err
		}
	}

	created, err := u.Get(ctx, adcore.ByDN(dn))
	if err != nil {
		return nil, err
	}
	return created, u.c.replicate(ctx, created.GUID)
}

func (u *userDirectory) Get(ctx context.Context, id adcore.Identity) (*adcore.User, error) {
	e, err := u.c.getOne(ctx, "User.Get", id, "user", userAttrs)
	if err != nil {
		return nil, err
	}
	m, err := u.model(e)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindTransport, Op: "User.Get", Err: err}
	}
	return m, nil
}

func (u *userDirectory) Search(ctx context.Context, q adcore.Query) ([]adcore.User, error) {
	const op = "User.Search"
	entries, err := u.c.searchEntries(ctx, op, q, "user", userAttrs)
	if err != nil {
		return nil, err
	}
	out := make([]adcore.User, 0, len(entries))
	for _, e := range entries {
		m, err := u.model(e)
		if err != nil {
			return nil, &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}
		out = append(out, *m)
	}
	return out, nil
}

func (u *userDirectory) Update(ctx context.Context, id adcore.Identity, spec adcore.UserSpec) (*adcore.User, error) {
	const op = "User.Update"
	if err := refuseUnimplemented(op, spec); err != nil {
		return nil, err
	}
	if err := spec.Validate(op); err != nil {
		return nil, err
	}

	unlock := u.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := u.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var mods []conn.Modification
	if spec.SamAccountName != "" && spec.SamAccountName != current.SamAccountName {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "sAMAccountName", Vals: [][]byte{[]byte(spec.SamAccountName)},
		})
	}
	mods = appendStringMod(mods, "userPrincipalName", spec.UserPrincipalName, current.UserPrincipalName)
	mods = appendStringMod(mods, "displayName", spec.DisplayName, current.DisplayName)
	mods = appendStringMod(mods, "givenName", spec.GivenName, current.GivenName)
	mods = appendStringMod(mods, "sn", spec.Surname, current.Surname)
	mods = appendStringMod(mods, "description", spec.Description, current.Description)

	// The current value is read first and only the named bits are moved, so a
	// change to one property cannot disturb another sharing the word.
	currentUAC := attrs.UACNormalAccount
	if !current.Enabled {
		currentUAC |= attrs.UACAccountDisable
	}
	if !current.PasswordExpires {
		currentUAC |= attrs.UACDontExpirePassword
	}
	if want := applyUAC(currentUAC, spec); want != currentUAC {
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "userAccountControl",
			Vals: [][]byte{[]byte(attrs.Uint32String(want))},
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

	if spec.ChangePasswordAtLogon != nil && *spec.ChangePasswordAtLogon != current.ChangePasswordAtLogon {
		v := "-1" // -1 stamps "now"; 0 means "must change at next logon"
		if *spec.ChangePasswordAtLogon {
			v = "0"
		}
		mods = append(mods, conn.Modification{
			Op: conn.ModReplace, Type: "pwdLastSet", Vals: [][]byte{[]byte(v)},
		})
	}

	if len(mods) > 0 {
		if err := u.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.Modify(ctx, current.DN, mods)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	name := current.Name
	if spec.Name != nil && *spec.Name != "" {
		name = *spec.Name
	}
	sameContainer, err := adcore.EqualFoldDN(spec.Container, current.Container)
	if err != nil {
		return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: op, Err: err}
	}
	if name != current.Name || !sameContainer {
		superior := ""
		if !sameContainer {
			superior = spec.Container
		}
		if err := u.c.withConn(ctx, op, func(cn conn.Conn) error {
			return cn.ModifyDN(ctx, current.DN, cnRDN(name), true, superior)
		}); err != nil {
			return nil, adcore.WithIdentity(err, op, id)
		}
	}

	if spec.Password != nil && !spec.Password.IsZero() {
		if err := u.setPasswordLocked(ctx, op, adcore.ByGUID(current.GUID), *spec.Password); err != nil {
			return nil, err
		}
	}

	updated, err := u.Get(ctx, adcore.ByGUID(current.GUID))
	if err != nil {
		return nil, err
	}
	return updated, u.c.replicate(ctx, updated.GUID)
}

func (u *userDirectory) Delete(ctx context.Context, id adcore.Identity) error {
	const op = "User.Delete"

	unlock := u.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	current, err := u.Get(ctx, id)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return err
	}
	if err := u.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Delete(ctx, current.DN)
	}); err != nil {
		return adcore.WithIdentity(err, op, id)
	}

	_, err = u.Get(ctx, adcore.ByGUID(current.GUID))
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

// SetPassword replaces unicodePwd, which AD accepts only as the password
// wrapped in double quotes and encoded UTF-16LE, and only over a protected
// connection. This package always has TLS, so the second condition holds by
// construction.
func (u *userDirectory) SetPassword(ctx context.Context, id adcore.Identity, password adcore.Secret) error {
	const op = "User.SetPassword"

	unlock := u.c.locks.Lock(adcore.IdentityArg(id))
	defer unlock()

	return u.setPasswordLocked(ctx, op, id, password)
}

// setPasswordLocked is the body, for the callers already holding the lock.
func (u *userDirectory) setPasswordLocked(ctx context.Context, op string, id adcore.Identity, password adcore.Secret) error {
	if password.IsZero() {
		return &adcore.Error{Kind: adcore.KindPassword, Op: op,
			Err: errors.New("an empty password cannot be set")}
	}
	dn, err := u.c.resolveDN(ctx, op, id)
	if err != nil {
		return err
	}
	encoded := utf16LEQuoted(adcore.RevealSecret(password))
	err = u.c.withConn(ctx, op, func(cn conn.Conn) error {
		return cn.Modify(ctx, dn, []conn.Modification{
			{Op: conn.ModReplace, Type: "unicodePwd", Vals: [][]byte{encoded}},
		})
	})
	if err != nil {
		return adcore.WithIdentity(err, op, id)
	}
	return nil
}

// utf16LEQuoted renders a password the way unicodePwd requires. Surrogate
// pairs are handled by utf16.Encode, so a password containing an astral
// character is not corrupted into something nobody can type.
func utf16LEQuoted(s string) []byte {
	units := utf16.Encode([]rune(`"` + s + `"`))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}
