package adldap

import (
	"context"
	"fmt"
	"time"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/attrs"
	"github.com/nemethhh/go-adldap/internal/conn"
)

const (
	defaultReplicationTimeout = 60 * time.Second
	defaultPollInterval       = 2 * time.Second
)

// replicate waits for a written object to appear on the configured targets.
//
// Replication is a property of domain topology, not of any single object, so
// it is configured once on the client. When it times out the caller receives
// the model alongside ErrReplication: the object exists and only the wait did
// not finish, so returning an error without the model would orphan it.
func (c *core) replicate(ctx context.Context, guid string) error {
	if !c.repl.Wait {
		return nil
	}

	timeout := c.repl.Timeout
	if timeout <= 0 {
		timeout = defaultReplicationTimeout
	}
	poll := c.repl.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}

	targets, err := c.replicationTargets(ctx)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return nil
	}

	guidBytes, err := attrs.GUIDToBytes(guid)
	if err != nil {
		return &adcore.Error{Kind: adcore.KindTransport, Op: "replicate", Err: err}
	}
	filter := "(objectGUID=" + escapeBinary(guidBytes) + ")"

	deadline := time.Now().Add(timeout)
	pending := append([]string(nil), targets...)

	for {
		var still []string
		for _, target := range pending {
			if c.repl.ForceSync {
				// Best effort: a sync that cannot be requested still leaves
				// the poll below to observe natural replication.
				_ = c.forceSync(ctx, guid, target)
			}
			present, err := c.objectPresentOn(ctx, target, filter)
			if err != nil || !present {
				still = append(still, target)
			}
		}
		if len(still) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return &adcore.Error{
				Kind: adcore.KindReplication, Op: "replicate", Identity: "guid:" + guid,
				Err: fmt.Errorf("the object did not appear on %v within %s; it exists on %s",
					still, timeout, c.server),
			}
		}
		pending = still

		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return &adcore.Error{Kind: adcore.KindTransport, Op: "replicate", Err: ctx.Err()}
		case <-t.C:
		}
	}
}

// replicationTargets resolves the configured targets. The single element "all"
// means every DC the configuration naming context lists, minus the pinned one,
// which by definition already has the write.
func (c *core) replicationTargets(ctx context.Context) ([]string, error) {
	if len(c.repl.Targets) != 1 || c.repl.Targets[0] != "all" {
		out := make([]string, 0, len(c.repl.Targets))
		for _, t := range c.repl.Targets {
			if t != c.server {
				out = append(out, t)
			}
		}
		return out, nil
	}

	var hosts []string
	err := c.withConn(ctx, "dclist", func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN:     "CN=Configuration," + c.dnc,
			Scope:      conn.ScopeSubtree,
			Filter:     "(objectClass=nTDSDSA)",
			Attributes: []string{"dNSHostName", "distinguishedName"},
			SizeLimit:  128,
		})
		if err != nil {
			return err
		}
		for _, e := range res.Entries {
			if h := e.FirstString("dNSHostName"); h != "" && h != c.server {
				hosts = append(hosts, h)
			}
		}
		return nil
	})
	return hosts, err
}

// objectPresentOn opens a short-lived connection to another DC and looks for
// the object. It deliberately does not use the pool, which is bound to the
// pinned DC.
func (c *core) objectPresentOn(ctx context.Context, host, filter string) (bool, error) {
	cn, err := c.dialOther(ctx, host)
	if err != nil {
		return false, err
	}
	defer cn.Close()

	res, err := cn.Search(ctx, conn.SearchRequest{
		BaseDN: c.dnc, Scope: conn.ScopeSubtree,
		Filter: filter, Attributes: []string{"distinguishedName"}, SizeLimit: 1,
	})
	if err != nil {
		return false, err
	}
	return len(res.Entries) > 0, nil
}

// forceSync asks the pinned DC to replicate one object to a target, via the
// rootDSE replicateSingleObject operational attribute.
//
// This is the operation the PSOpenAD dialect had to refuse, which is why
// force_sync is rejected there and accepted here.
func (c *core) forceSync(ctx context.Context, guid, target string) error {
	value := target + ":" + guid
	return c.withConn(ctx, "replicate_force", func(cn conn.Conn) error {
		return cn.Modify(ctx, "", []conn.Modification{{
			Op: conn.ModReplace, Type: "replicateSingleObject", Vals: [][]byte{[]byte(value)},
		}})
	})
}
