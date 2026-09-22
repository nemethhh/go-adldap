package conn

import (
	"errors"
	"fmt"
	"os"

	"github.com/oiweiwei/gokrb5.fork/v9/client"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/keytab"
	"github.com/oiweiwei/gokrb5.fork/v9/messages"
	"github.com/oiweiwei/gokrb5.fork/v9/types"
)

// ticketSource is the Kerberos library behind a narrow seam, so that swapping
// it is a one-file change the way swapping go-ldap is a one-package change.
//
// The signatures carry the library's own message types rather than this
// package's. That is deliberate: a total abstraction would mean re-declaring
// the Kerberos protocol messages, which is a large amount of code to carry for
// a swap that may never happen. What the seam does buy is that every *call
// site* is in this file.
type ticketSource interface {
	// ServiceTicket obtains a ticket for an SPN, with its session key.
	ServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error)
	// Realm and CName name the authenticated principal, for the authenticator.
	Realm() string
	CName() types.PrincipalName
	// Client exposes the underlying client, which the GSSAPI token builder
	// needs because the library's token constructor takes one.
	Client() *client.Client
	// Destroy zeroes the credential material. A fresh source is built per
	// bind, so this leaves the Binder reusable for the pool's reconnect.
	Destroy()
}

// ticketSourceOptions is everything a credential source can be built from.
// At most one of CCachePath, Keytab and Password is set; Config.Validate
// enforces that above this package, and with none set KRB5CCNAME applies.
type ticketSourceOptions struct {
	CCachePath string
	Keytab     string
	Password   string
	Username   string
	// Realm is always populated on the normal path: client.go's binderForHost
	// derives it from Config.Server, deliberately never from the dialled host,
	// before KerberosBinder (and, through it, ticketSourceOptions) is ever
	// built — see the comment on that derivation. The fallback below that
	// derives Realm from KDC when this is left empty is reached only by a
	// caller inside this package that constructs ticketSourceOptions directly
	// rather than through client.go — this file's own tests, for instance.
	// That caller supplies KDC and Realm together and is not juggling a
	// second, differently realmed controller behind it the way client.go's
	// replication probe does, so the concern that derivation warns about does
	// not apply here: KDC is a safe, and the only available, fallback.
	Realm        string
	Krb5ConfPath string
	// KDC is the pinned domain controller, used both as the KDC in a
	// synthesized krb5.conf and to derive a realm when none is configured.
	KDC    string
	Getenv func(string) string
}

// gokrb5Source is the one implementation, over github.com/oiweiwei/gokrb5.fork.
//
// The fork rather than jcmturner/gokrb5 because the latter's last commit was
// 2022-10-18: its issue asking for channel binding has gone unanswered since
// January 2025. The fork is signature-compatible and its two most recent
// fixes — AP-REQ realm verification and AP-REP marshal parity — are in exactly
// the code path this package now builds by hand.
type gokrb5Source struct{ cl *client.Client }

var _ ticketSource = (*gokrb5Source)(nil)

func (s *gokrb5Source) ServiceTicket(spn string) (messages.Ticket, types.EncryptionKey, error) {
	return s.cl.GetServiceTicket(spn)
}
func (s *gokrb5Source) Realm() string              { return s.cl.Credentials.Realm() }
func (s *gokrb5Source) CName() types.PrincipalName { return s.cl.Credentials.CName() }
func (s *gokrb5Source) Client() *client.Client     { return s.cl }
func (s *gokrb5Source) Destroy()                   { s.cl.Destroy() }

// newTicketSource builds the credential source the options select. Resolution
// order is keytab, then password, then credential cache — explicit
// configuration before the ambient environment.
func newTicketSource(o ticketSourceOptions) (ticketSource, error) {
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	realm := o.Realm
	if realm == "" {
		realm = RealmFromServer(o.KDC)
	}

	krb5conf, err := loadKrb5Conf(o.Krb5ConfPath, realm, o.KDC, os.Stat)
	if err != nil {
		return nil, err
	}

	switch {
	case o.Keytab != "":
		if o.Username == "" {
			return nil, errors.New("adldap: Kerberos.Keytab requires Kerberos.Username")
		}
		kt, err := keytab.Load(o.Keytab)
		if err != nil {
			return nil, fmt.Errorf("adldap: reading the keytab at %s: %w", o.Keytab, err)
		}
		return &gokrb5Source{cl: client.NewWithKeytab(o.Username, realm, kt, krb5conf, krbSettings()...)}, nil

	case o.Password != "":
		if o.Username == "" {
			return nil, errors.New(
				"adldap: Kerberos.Password requires Kerberos.Username — the AS-REQ has no " +
					"client name without it, and the KDC reports an unknown principal rather " +
					"than a missing one")
		}
		return &gokrb5Source{cl: client.NewWithPassword(o.Username, realm, o.Password, krb5conf, krbSettings()...)}, nil

	default:
		path, err := ResolveCCachePath(o.CCachePath, getenv)
		if err != nil {
			return nil, err
		}
		cc, err := credentials.LoadCCache(path)
		if err != nil {
			return nil, fmt.Errorf("adldap: reading the credential cache at %s: %w", path, err)
		}
		cl, err := client.NewFromCCache(cc, krb5conf, krbSettings()...)
		if err != nil {
			return nil, err
		}
		return &gokrb5Source{cl: cl}, nil
	}
}

// krbSettings are the client settings every source shares.
//
// PA-FX-FAST is disabled because Active Directory does not offer it and the
// library's probe for it costs an extra KDC round trip that can fail outright
// on some domain functional levels. The reference implementation this package
// follows does the same.
func krbSettings() []func(*client.Settings) {
	return []func(*client.Settings){client.DisablePAFXFAST(true)}
}
