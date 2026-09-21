package conn

import (
	"errors"
	"fmt"
	"strings"
)

// knownCCacheTypes are the credential-cache types MIT Kerberos names in
// KRB5CCNAME. Matching against this list rather than "anything before a colon"
// keeps a Windows path like C:\Users\svc\krb5cc from being read as a "C" cache
// type, which would tell the operator to fix something they never configured.
var knownCCacheTypes = []string{"FILE", "DIR", "KEYRING", "KCM", "MEMORY", "MSLSA", "API"}

// ResolveCCachePath finds the credential cache to bind with: an explicit path
// wins, otherwise KRB5CCNAME.
//
// Only FILE caches are readable. gokrb5 loads a ccache with os.ReadFile, so
// the KEYRING, KCM and DIR types have no code path at all — and those are the
// defaults on sssd-managed RHEL, Fedora and Ubuntu, so this is the failure an
// operator who did everything right will hit first. The error names the fix.
func ResolveCCachePath(explicit string, getenv func(string) string) (string, error) {
	raw := strings.TrimSpace(explicit)
	if raw == "" {
		raw = strings.TrimSpace(getenv("KRB5CCNAME"))
	}
	if raw == "" {
		return "", errors.New(
			"adldap: no Kerberos credential cache: set KRB5CCNAME, or run " +
				`KRB5CCNAME=FILE:/tmp/krb5cc_tf kinit <user>@<REALM>`)
	}
	// An explicit path goes through exactly the same normalization as the
	// environment's. A caller may legitimately write "FILE:/tmp/krb5cc" in
	// configuration, and a consumer that resolves KRB5CCNAME itself — which
	// the Terraform provider does, because configuration wins over the
	// environment there — hands the raw value in through this argument. An
	// explicit branch that returned it verbatim left the FILE: prefix in the
	// filename and failed with "open FILE:/tmp/krb5cc_tf: no such file".
	i := strings.Index(raw, ":")
	if i <= 0 {
		return raw, nil
	}
	scheme := strings.ToUpper(raw[:i])
	if scheme == "FILE" {
		return raw[i+1:], nil
	}
	for _, known := range knownCCacheTypes {
		if scheme == known {
			return "", fmt.Errorf(
				"adldap: KRB5CCNAME names a %s credential cache, which cannot be read from Go "+
					"(only FILE caches can be). Re-obtain the ticket into a file: "+
					`KRB5CCNAME=FILE:/tmp/krb5cc_tf kinit <user>@<REALM>, then run Terraform `+
					"with that same KRB5CCNAME", scheme)
		}
	}
	// Not a cache type this or any MIT Kerberos build names — a drive letter,
	// most likely. Take it as a path.
	return raw, nil
}
