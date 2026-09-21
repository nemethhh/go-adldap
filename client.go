package adldap

import (
	"context"
	"errors"
	"time"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
)

// Client is the entry point. Hand it to a consumer through Directory.
type Client struct {
	core *core
}

const defaultTimeout = 60 * time.Second

// New validates the configuration, opens and binds one connection, reads the
// rootDSE, and pins the domain controller this client targets for its
// lifetime. It performs one round trip.
//
// The DC is pinned rather than rediscovered because a create that lands on
// DC-A and a read-back that hits DC-B reports "not found". Config.Server names
// it; there is deliberately no discovery.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dial, binder, err := cfg.dialer()
	if err != nil {
		return nil, err
	}
	other, err := cfg.otherDialer()
	if err != nil {
		return nil, err
	}
	return newClient(ctx, cfg, dial, binder, other)
}

// NewWithConn builds a Client over a caller-supplied connection factory rather
// than dialling one.
//
// It exists because the in-process LDAP server this module tests against
// cannot serve ModifyDN — the library behind it parses no such request — and
// ModifyDN is how a rename and a move happen. Without a seam here, the
// rename-and-move contract could be tested only against a real domain. The
// factory's type names an internal package, so nothing outside this module can
// supply one.
func NewWithConn(ctx context.Context, cfg Config, dial func(context.Context) (conn.Conn, error)) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return newClient(ctx, cfg, dial, noBinder{}, func(ctx context.Context, _ string) (conn.Conn, error) {
		return dial(ctx)
	})
}

// noBinder satisfies the Binder contract for a connection that is already
// authenticated by construction.
type noBinder struct{}

func (noBinder) Bind(context.Context, conn.Conn) error { return nil }
func (noBinder) Describe() string                      { return "pre-bound connection" }

// dialer builds the real TLS dialler and the configured Binder.
func (cfg Config) dialer() (func(context.Context) (conn.Conn, error), conn.Binder, error) {
	port := cfg.Port
	if port == 0 {
		port = DefaultPort(cfg.TLS)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		var err error
		tlsCfg, err = conn.BuildTLSConfig(cfg.Server, cfg.CACertificateFile, cfg.InsecureSkipVerify)
		if err != nil {
			return nil, nil, &adcore.Error{Kind: adcore.KindConstraint, Op: "New", Err: err}
		}
	}

	binder, err := cfg.binder()
	if err != nil {
		return nil, nil, err
	}

	return func(ctx context.Context) (conn.Conn, error) {
		return conn.Dial(ctx, conn.DialOptions{
			Host:      cfg.Server,
			Port:      port,
			StartTLS:  cfg.TLS == TLSStartTLS,
			TLSConfig: tlsCfg,
			Timeout:   timeout,
		})
	}, binder, nil
}

// newClient opens the pool, reads the rootDSE and pins the DC.
func newClient(ctx context.Context, cfg Config, dial func(context.Context) (conn.Conn, error), binder conn.Binder, dialOther func(context.Context, string) (conn.Conn, error)) (*Client, error) {
	pool := conn.NewPool(conn.PoolOptions{
		Dial:   dial,
		Binder: binder,
		Size:   cfg.MaxConcurrency,
	})

	c := &core{
		pool:      pool,
		dialOther: dialOther,
		server:    cfg.Server,
		retry:     cfg.Retry.WithDefaults(),
		repl:      cfg.Replication,
		locks:     adcore.NewKeyedMutex(),
		log:       cfg.Log,
	}

	var dnc, schemaNC, configNC string
	err := c.withConn(ctx, "New", func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN: "",
			Scope:  conn.ScopeBase,
			Filter: "(objectClass=*)",
			Attributes: []string{"defaultNamingContext", "dnsHostName",
				"schemaNamingContext", "configurationNamingContext"},
		})
		if err != nil {
			return err
		}
		if len(res.Entries) == 0 {
			return errors.New("the rootDSE returned no entry")
		}
		dnc = res.Entries[0].FirstString("defaultNamingContext")
		schemaNC = res.Entries[0].FirstString("schemaNamingContext")
		configNC = res.Entries[0].FirstString("configurationNamingContext")
		return nil
	})
	if err != nil {
		pool.Close()
		return nil, err
	}
	if dnc == "" {
		pool.Close()
		return nil, &adcore.Error{
			Kind: adcore.KindTransport, Op: "New",
			Err: errors.New("adldap: the rootDSE returned no defaultNamingContext"),
		}
	}
	c.dnc = dnc
	c.schemaNC = schemaNC
	c.configNC = configNC

	return &Client{core: c}, nil
}

// binder turns the configured auth block into a conn.Binder for the pinned DC.
func (c Config) binder() (conn.Binder, error) { return c.binderForHost(c.Server) }

// binderForHost is binder for a specific host. The host matters to Kerberos and
// only to Kerberos: the SPN defaults to ldap/<host>, so reusing the pinned DC's
// binder against a second controller presents a ticket for the wrong service.
// AD refuses it, the replication probe never sees the object, and the wait spins
// to its deadline — a timeout that looks like slow replication and is actually a
// bad SPN.
func (c Config) binderForHost(host string) (conn.Binder, error) {
	switch {
	case c.Simple != nil:
		return conn.SimpleBinder{
			Username: c.Simple.Username,
			Password: adcore.RevealSecret(c.Simple.Password),
		}, nil
	case c.Kerberos != nil:
		return conn.KerberosBinder{
			CCachePath:   c.Kerberos.CCachePath,
			Keytab:       c.Kerberos.Keytab,
			Username:     c.Kerberos.Username,
			Realm:        c.Kerberos.Realm,
			Krb5ConfPath: c.Kerberos.Krb5ConfPath,
			SPN:          c.Kerberos.SPN,
			Host:         host,
		}, nil
	case c.NTLM != nil:
		return conn.NTLMBinder{
			Domain:   c.NTLM.Domain,
			Username: c.NTLM.Username,
			Password: adcore.RevealSecret(c.NTLM.Password),
		}, nil
	}
	return nil, constraint("no auth block; Validate should have caught this")
}

// Server returns the pinned domain controller.
func (c *Client) Server() string { return c.core.server }

// DefaultNamingContext returns the domain's naming context.
func (c *Client) DefaultNamingContext() string { return c.core.dnc }

// Close releases the connection pool.
func (c *Client) Close() error { return c.core.pool.Close() }

// Directory presents this client through the backend-neutral contract.
//
// The classes this backend does not implement are filled with stubs that
// return KindUnsupported, naming the class. They were nil interface fields
// until the lab showed what that actually costs: a consumer dereferences the
// nil and panics, which aborted an entire acceptance run and named neither the
// class nor the reason.
func (c *Client) Directory() adcore.Directory {
	return adcore.Directory{
		OU:             &ouDirectory{c: c.core},
		Group:          &groupDirectory{c: c.core},
		User:           &userDirectory{c: c.core},
		ServiceAccount: &serviceAccountDirectory{c: c.core},
		Computer:       &computerDirectory{c: c.core},
		ACL:            &aclDirectory{c: c.core},
		Schema:         &schemaDirectory{c: c.core},
		Server:         c.core.server,
		DNC:            c.core.dnc,
		Closer:         c,
	}
}

// otherDialer dials a DC other than the pinned one, with the same TLS
// configuration, port and bind. It is used only by the replication wait, which
// has to observe a write arriving somewhere the pool never goes.
func (cfg Config) otherDialer() (func(context.Context, string) (conn.Conn, error), error) {
	port := cfg.Port
	if port == 0 {
		port = DefaultPort(cfg.TLS)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return func(ctx context.Context, host string) (conn.Conn, error) {
		// The certificate is verified against the host actually being
		// reached, not against the pinned one, or every target beyond the
		// first would fail the name check.
		tlsCfg := cfg.TLSConfig
		if tlsCfg == nil {
			var err error
			tlsCfg, err = conn.BuildTLSConfig(host, cfg.CACertificateFile, cfg.InsecureSkipVerify)
			if err != nil {
				return nil, err
			}
		} else {
			clone := tlsCfg.Clone()
			clone.ServerName = host
			tlsCfg = clone
		}
		// The binder is rebuilt for this host, not reused: an explicit SPN
		// still wins, but the default follows the host actually dialled.
		binder, err := cfg.binderForHost(host)
		if err != nil {
			return nil, err
		}
		cn, err := conn.Dial(ctx, conn.DialOptions{
			Host: host, Port: port, StartTLS: cfg.TLS == TLSStartTLS,
			TLSConfig: tlsCfg, Timeout: timeout,
		})
		if err != nil {
			return nil, err
		}
		if err := binder.Bind(ctx, cn); err != nil {
			cn.Close()
			return nil, err
		}
		return cn, nil
	}, nil
}
