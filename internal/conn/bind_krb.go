package conn

import (
	"context"
	"fmt"
	"os"
	"strings"

	ldapgssapi "github.com/go-ldap/ldap/v3/gssapi"
)

// KerberosBinder binds with a Kerberos ticket. The intended path is the
// ambient credential cache: an operator runs kinit in their own shell and no
// password reaches Terraform configuration. Keytab is the unattended
// alternative for CI.
//
// This is the Linux and macOS path. Windows keeps credentials in the LSA with
// no readable ccache, so a Windows operator uses simple or NTLM until an SSPI
// client lands behind this seam.
type KerberosBinder struct {
	CCachePath   string
	Keytab       string
	Username     string
	Realm        string
	Krb5ConfPath string
	SPN          string // defaults to ldap/<host>

	Host   string
	Getenv func(string) string
}

var _ Binder = KerberosBinder{}

func (b KerberosBinder) Describe() string {
	if b.Keytab != "" {
		return fmt.Sprintf("GSSAPI bind as %s@%s from keytab", b.Username, b.Realm)
	}
	return "GSSAPI bind from the ambient credential cache"
}

func (b KerberosBinder) spn() string {
	if b.SPN != "" {
		return b.SPN
	}
	return "ldap/" + b.Host
}

func (b KerberosBinder) krb5Conf() string {
	if b.Krb5ConfPath != "" {
		return b.Krb5ConfPath
	}
	return "/etc/krb5.conf"
}

func (b KerberosBinder) Bind(ctx context.Context, c Conn) error {
	g, ok := c.(*goldapConn)
	if !ok {
		return errWrongConn("KerberosBinder")
	}

	getenv := b.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	var (
		client *ldapgssapi.Client
		err    error
	)
	if b.Keytab != "" {
		client, err = ldapgssapi.NewClientWithKeytab(b.Username, b.Realm, b.Keytab, b.krb5Conf())
	} else {
		var path string
		path, err = ResolveCCachePath(b.CCachePath, getenv)
		if err != nil {
			return err
		}
		client, err = ldapgssapi.NewClientFromCCache(path, b.krb5Conf())
	}
	if err != nil {
		return annotateTicketError(err)
	}
	// Close over DeleteSecContext: DeleteSecContext clears only the session
	// subkeys, while Close calls Destroy and zeroes the credential material
	// read out of the ccache too. A fresh client is built on every Bind, so
	// destroying this one leaves the Binder reusable for the pool's
	// reconnect — which is what the Binder contract requires.
	defer client.Close()

	return annotateTicketError(toRawError(g.l.GSSAPIBind(client, b.spn(), "")))
}

// annotateTicketError turns gokrb5's terse failures into something an operator
// can act on. A TGT that has expired mid-apply is the common one: AD's default
// ticket lifetime is ten hours and gokrb5 does not renew, so a long apply can
// outlive its own credential.
func annotateTicketError(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "TGT not found in CCache"):
		return fmt.Errorf("%w: the credential cache holds no ticket-granting ticket; run kinit again", err)
	case strings.Contains(msg, "expired"), strings.Contains(msg, "Ticket expired"):
		return fmt.Errorf("%w: the Kerberos ticket has expired; run kinit again "+
			"(AD's default ticket lifetime is 10 hours and it is not renewed automatically)", err)
	}
	return err
}
