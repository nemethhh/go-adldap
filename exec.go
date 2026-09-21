package adldap

import (
	"context"
	"errors"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/ldaperr"
)

type core struct {
	pool   *conn.Pool
	server string
	dnc    string

	// schemaNC and configNC are the other two naming contexts Schema.Resolve
	// searches. Like dnc they are read once at New and are constant for the
	// client's lifetime under a pinned DC.
	schemaNC string
	configNC string

	// dialOther opens a short-lived connection to a DC other than the pinned
	// one, for the replication wait. The pool cannot serve it: every pooled
	// connection is bound to Server for the client's lifetime, which is the
	// invariant that keeps a write and its read-back on one DC.
	dialOther func(ctx context.Context, host string) (conn.Conn, error)

	retry adcore.RetryConfig
	repl  ReplicationConfig
	locks *adcore.KeyedMutex
	log   Logger

	// dsid caches the domain SID, which every principal descriptor needs and
	// which cannot change under a pinned DC.
	dsid domainSIDCache
}

// withConn runs one operation on a pooled connection, classifies its failure,
// and retries only while the error is KindTransient.
//
// A transport failure discards the connection rather than returning it: the
// next acquirer must not inherit a dead socket. Retrying anything other than
// KindTransient is forbidden — that Kind's contract is the only one
// guaranteeing the operation provably did not execute, so it is the only one
// where re-issuing cannot duplicate a side effect.
func (c *core) withConn(ctx context.Context, op string, fn func(conn.Conn) error) error {
	var lastErr error
	for attempt := 1; attempt <= c.retry.MaxAttempts; attempt++ {
		lease, err := c.pool.Acquire(ctx)
		if err != nil {
			return &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
		}

		lastErr = ldaperr.Classify(op, fn(lease.Conn()))

		var e *adcore.Error
		if errors.As(lastErr, &e) && e.Kind == adcore.KindTransport {
			lease.Discard()
		} else {
			lease.Release()
		}

		if lastErr == nil {
			return nil
		}
		if !errors.As(lastErr, &e) || !e.Kind.Retryable() || attempt == c.retry.MaxAttempts {
			return lastErr
		}
		c.debug(ctx, "adldap: retrying transient failure", "op", op, "attempt", attempt, "error", lastErr.Error())
		if err := adcore.Backoff(ctx, c.retry, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

func (c *core) debug(ctx context.Context, msg string, kv ...any) {
	if c.log == nil {
		return
	}
	c.log.Debug(ctx, msg, kv...)
}

// isNotFound reports whether err is the not-found condition.
func isNotFound(err error) bool { return err != nil && errors.Is(err, adcore.ErrNotFound) }
