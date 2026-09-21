package adldap_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestUserEnabledAndPasswordExpiresAreUACBits(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("jdoe"), SamAccountName: "jdoe", Container: d.DNC,
		Enabled:         adcore.Bool(false),
		PasswordExpires: adcore.Bool(false),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Enabled {
		t.Error("Enabled = true, want false")
	}
	if u.PasswordExpires {
		t.Error("PasswordExpires = true, want false")
	}

	updated, err := d.User.Update(ctx, adcore.ByGUID(u.GUID), adcore.UserSpec{
		Name: adcore.String("jdoe"), SamAccountName: "jdoe", Container: d.DNC,
		Enabled:         adcore.Bool(true),
		PasswordExpires: adcore.Bool(false),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !updated.Enabled {
		t.Error("Enabled = false after enabling")
	}
	if updated.PasswordExpires {
		t.Error("enabling the account flipped PasswordExpires; the UAC bits must be edited independently")
	}
}

// The sharper form of the same rule: a spec that names only Enabled must leave
// every other bit exactly as it was.
func TestUpdatingOneUACBitLeavesTheOthersAlone(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("bits"), SamAccountName: "bits", Container: d.DNC,
		PasswordExpires: adcore.Bool(false),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := d.User.Update(ctx, adcore.ByGUID(u.GUID), adcore.UserSpec{
		Name: adcore.String("bits"), SamAccountName: "bits", Container: d.DNC,
		Enabled: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.PasswordExpires {
		t.Error("a spec naming only Enabled turned password expiry back on")
	}
}

func TestUserAccountExpirationNeverIsNil(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("noexp"), SamAccountName: "noexp", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.AccountExpiration != nil {
		t.Errorf("AccountExpiration = %v, want nil for never", u.AccountExpiration)
	}

	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	updated, err := d.User.Update(ctx, adcore.ByGUID(u.GUID), adcore.UserSpec{
		Name: adcore.String("noexp"), SamAccountName: "noexp", Container: d.DNC,
		AccountExpiration: adcore.SetTime(want),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.AccountExpiration == nil || !updated.AccountExpiration.Equal(want) {
		t.Errorf("AccountExpiration = %v, want %v", updated.AccountExpiration, want)
	}

	cleared, err := d.User.Update(ctx, adcore.ByGUID(u.GUID), adcore.UserSpec{
		Name: adcore.String("noexp"), SamAccountName: "noexp", Container: d.DNC,
		AccountExpiration: adcore.ClearTime(),
	})
	if err != nil {
		t.Fatalf("Update clearing the expiry: %v", err)
	}
	if cleared.AccountExpiration != nil {
		t.Errorf("AccountExpiration = %v after clearing, want nil", cleared.AccountExpiration)
	}
}

// unicodePwd is written as the password wrapped in double quotes and encoded
// UTF-16LE. Anything else is rejected by AD, and a silently wrong encoding
// would set a password nobody can use.
func TestSetPasswordUsesQuotedUTF16LE(t *testing.T) {
	ctx := context.Background()
	srv := adtest.StartMemory(t)
	d := srv.Directory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("pw"), SamAccountName: "pw", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := d.User.SetPassword(ctx, adcore.ByGUID(u.GUID), adcore.NewSecret("P@ssw0rd!")); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	raw := srv.Entries()["CN=pw,"+d.DNC]["unicodePwd"]
	if len(raw) != 1 {
		t.Fatalf("unicodePwd has %d values, want 1", len(raw))
	}
	want := utf16LE(`"P@ssw0rd!"`)
	if string(raw[0]) != string(want) {
		t.Errorf("unicodePwd = % x, want % x (quoted, UTF-16LE)", raw[0], want)
	}
}

// A password outside the BMP must survive as a surrogate pair rather than
// being mangled into something nobody can type.
func TestSetPasswordHandlesAstralCharacters(t *testing.T) {
	ctx := context.Background()
	srv := adtest.StartMemory(t)
	d := srv.Directory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("astral"), SamAccountName: "astral", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const pw = "pa\U0001F600ss"
	if err := d.User.SetPassword(ctx, adcore.ByGUID(u.GUID), adcore.NewSecret(pw)); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	raw := srv.Entries()["CN=astral,"+d.DNC]["unicodePwd"][0]
	if want := utf16LE(`"` + pw + `"`); string(raw) != string(want) {
		t.Errorf("unicodePwd = % x, want % x", raw, want)
	}
}

// utf16LE encodes with explicit surrogate handling, so it is an independent
// check on the implementation rather than a copy of it.
func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
			continue
		}
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestSetPasswordRefusesEmpty(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)
	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("nopw"), SamAccountName: "nopw", Container: d.DNC,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	err = d.User.SetPassword(ctx, adcore.ByGUID(u.GUID), adcore.NewSecret(""))
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindPassword {
		t.Fatalf("want KindPassword, got %#v", err)
	}
}

// can_change_password is an ACE pair, which Phase 5 implements. Until then a
// spec that asks for it must say so rather than quietly ignore the request.
func TestCannotChangePasswordIsUnsupportedForNow(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	_, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("acl"), SamAccountName: "acl", Container: d.DNC,
		CanChangePassword: adcore.Bool(false),
	})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindUnsupported {
		t.Fatalf("want KindUnsupported, got %#v", err)
	}
}

// AD refuses to create an enabled account with no password, and refuses to
// stamp pwdLastSet on one — both with ERROR_PASSWORD_RESTRICTION, which
// surfaces as "password rejected by domain policy" and blames a password that
// was never the problem. The account is therefore created disabled and enabled
// afterwards, which is the order New-ADUser uses. Found on the lab.
func TestUserCreateEnabledWithPassword(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	u, err := d.User.Create(ctx, adcore.UserSpec{
		Name: adcore.String("live"), SamAccountName: "live", Container: d.DNC,
		Enabled:               adcore.Bool(true),
		Password:              secretPtr("Correct-Horse-Battery-Staple-1"),
		ChangePasswordAtLogon: adcore.Bool(true),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !u.Enabled {
		t.Error("Enabled = false after creating an enabled account")
	}
	if !u.ChangePasswordAtLogon {
		t.Error("ChangePasswordAtLogon = false after asking for it")
	}
}

func secretPtr(s string) *adcore.Secret {
	sec := adcore.NewSecret(s)
	return &sec
}
