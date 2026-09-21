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
			return nil, &adcore.Error{Kind: adcore.KindConstraint, Op: "New", Err: err}
		}
	}

	binder, err := cfg.binder()
	if err != nil {
		return nil, err
	}

	pool := conn.NewPool(conn.PoolOptions{
		Dial: func(ctx context.Context) (conn.Conn, error) {
			return conn.Dial(ctx, conn.DialOptions{
				Host:      cfg.Server,
				Port:      port,
				StartTLS:  cfg.TLS == TLSStartTLS,
				TLSConfig: tlsCfg,
				Timeout:   timeout,
			})
		},
		Binder: binder,
		Size:   cfg.MaxConcurrency,
	})

	c := &core{
		pool:   pool,
		server: cfg.Server,
		retry:  cfg.Retry.WithDefaults(),
		repl:   cfg.Replication,
		locks:  adcore.NewKeyedMutex(),
		log:    cfg.Log,
	}

	var dnc string
	err = c.withConn(ctx, "New", func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN:     "",
			Scope:      conn.ScopeBase,
			Filter:     "(objectClass=*)",
			Attributes: []string{"defaultNamingContext", "dnsHostName", "schemaNamingContext"},
		})
		if err != nil {
			return err
		}
		if len(res.Entries) == 0 {
			return errors.New("the rootDSE returned no entry")
		}
		dnc = res.Entries[0].FirstString("defaultNamingContext")
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

	return &Client{core: c}, nil
}

// binder turns the configured auth block into a conn.Binder.
func (c Config) binder() (conn.Binder, error) {
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
			Host:         c.Server,
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
// The per-class sub-directories are nil until Phase 2 lands them: a nil
// interface field is an honest "not implemented yet" that fails loudly at the
// first call, where a stub that returned an error would be dead code nobody
// noticed shipping. Server, DNC and Close are live now, which is what the
// connection layer's own tests need.
func (c *Client) Directory() adcore.Directory {
	return adcore.Directory{
		Server: c.core.server,
		DNC:    c.core.dnc,
		Closer: c,
	}
}
