package conn

import (
	"context"
	"errors"
	"fmt"
)

// Binder authenticates an already-dialled connection. A pooled connection that
// drops is re-dialled and re-bound with the same Binder, so a Binder must be
// safe to reuse and must not hold per-connection state.
type Binder interface {
	Bind(ctx context.Context, c Conn) error
	// Describe names the mechanism and principal for a log line. It must
	// never include a secret.
	Describe() string
}

// errWrongConn is what every Binder returns when handed a Conn it did not
// expect. The binds reach past the seam into the go-ldap connection — a bind
// is the one operation the Conn interface does not abstract, because each
// mechanism needs the library's own client object — so each must check.
func errWrongConn(mechanism string) error {
	return fmt.Errorf("adldap: %s requires the go-ldap connection", mechanism)
}

// SimpleBinder performs a simple bind. It is safe only because this package
// never dials without TLS.
type SimpleBinder struct {
	Username string
	Password string
}

var _ Binder = SimpleBinder{}

func (b SimpleBinder) Describe() string {
	return fmt.Sprintf("simple bind as %s", b.Username)
}

func (b SimpleBinder) Bind(ctx context.Context, c Conn) error {
	if b.Password == "" {
		// An empty password is an unauthenticated bind, which AD accepts and
		// which silently produces an anonymous session with almost no rights.
		// Refusing here is clearer than the access-denied that would follow
		// on the first write, a long way from its cause.
		return errors.New("adldap: simple bind with an empty password would bind anonymously")
	}
	g, ok := c.(*goldapConn)
	if !ok {
		return errWrongConn("SimpleBinder")
	}
	return toRawError(g.l.Bind(b.Username, b.Password))
}
