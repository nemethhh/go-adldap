package conn

import (
	"context"
	"fmt"
)

// NTLMBinder binds with NTLM, for a caller that cannot obtain a Kerberos TGT —
// no KDC reachability, no krb5.conf, a workgroup CI runner.
//
// Upstream go-ldap sends no channel-binding token, so on a domain with
// LdapEnforceChannelBinding set to 2 ("always") this bind is rejected even
// over TLS. That is a known and documented gap; the fix is a forked LDAP
// library, which this package's seam exists to make swappable.
type NTLMBinder struct {
	Domain   string
	Username string
	Password string
}

var _ Binder = NTLMBinder{}

func (b NTLMBinder) Describe() string {
	return fmt.Sprintf(`NTLM bind as %s\%s`, b.Domain, b.Username)
}

func (b NTLMBinder) Bind(ctx context.Context, c Conn) error {
	g, ok := c.(*goldapConn)
	if !ok {
		return errWrongConn("NTLMBinder")
	}
	return toRawError(g.l.NTLMBind(b.Domain, b.Username, b.Password))
}
