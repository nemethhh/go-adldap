package conn

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/oiweiwei/gokrb5.fork/v9/config"
)

// systemKrb5Conf is where MIT Kerberos keeps its configuration on Linux and
// macOS.
const systemKrb5Conf = "/etc/krb5.conf"

// loadKrb5Conf finds the Kerberos configuration to bind with.
//
// The order is: a path the caller named, then the system file, then a
// configuration synthesized from the realm and the pinned domain controller.
// That last step is what makes a supplied username and password usable at all.
// A caller who passes credentials has by definition not run kinit, and a host
// that has never run kinit generally has no /etc/krb5.conf either — a CI
// container, a Terraform Cloud runner. Requiring one there would leave the
// credential path working only where it was least needed.
//
// stat is injected so the precedence can be tested without touching the host's
// real configuration.
func loadKrb5Conf(explicitPath, realm, kdc string, stat func(string) (os.FileInfo, error)) (*config.Config, error) {
	if explicitPath != "" {
		cfg, err := config.Load(explicitPath)
		if err != nil {
			return nil, fmt.Errorf("adldap: reading the Kerberos configuration at %s: %w", explicitPath, err)
		}
		return cfg, nil
	}

	if _, err := stat(systemKrb5Conf); err == nil {
		cfg, err := config.Load(systemKrb5Conf)
		if err != nil {
			return nil, fmt.Errorf("adldap: reading %s: %w", systemKrb5Conf, err)
		}
		return cfg, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("adldap: checking for %s: %w", systemKrb5Conf, err)
	}

	text, err := synthesizeKrb5Conf(realm, kdc)
	if err != nil {
		return nil, err
	}
	cfg, err := config.NewFromString(text)
	if err != nil {
		return nil, fmt.Errorf("adldap: the synthesized Kerberos configuration did not parse: %w", err)
	}
	return cfg, nil
}

// synthesizeKrb5Conf writes a minimal configuration naming one realm and one
// KDC: the domain controller this client has already pinned.
//
// Both DNS lookups are off. A host with no krb5.conf has not had SRV discovery
// set up for our benefit either, and a lookup that fails costs a resolver
// timeout on every bind while producing a worse error than "the KDC refused
// us". The pinned server is the KDC we want regardless — the client sends
// every other request there too, and a ticket from a different controller is
// the DC-pinning bug this library exists to avoid.
//
// Encryption types are deliberately absent, so the library's own AES defaults
// apply. Naming them here would freeze a policy that belongs to the domain.
func synthesizeKrb5Conf(realm, kdc string) (string, error) {
	if realm == "" {
		return "", errors.New(
			"adldap: no Kerberos realm: set Kerberos.Realm, or name a krb5.conf with " +
				"Kerberos.Krb5ConfPath. A realm cannot be guessed — the wrong one sends the " +
				"request to the wrong KDC and reports the principal as unknown")
	}
	if kdc == "" {
		return "", errors.New("adldap: no KDC: Config.Server is required")
	}

	domain := strings.ToLower(realm)
	return fmt.Sprintf(`[libdefaults]
    default_realm = %[1]s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false

[realms]
    %[1]s = {
        kdc = %[2]s
    }

[domain_realm]
    .%[3]s = %[1]s
    %[3]s = %[1]s
`, realm, kdc, domain), nil
}

// RealmFromServer derives the Kerberos realm from a domain controller's name:
// the domain suffix, uppercased, which is the Active Directory convention.
// A bare host name yields nothing, because a host with no domain carries no
// realm to derive.
func RealmFromServer(server string) string {
	_, domain, found := strings.Cut(server, ".")
	if !found || domain == "" {
		return ""
	}
	return strings.ToUpper(domain)
}
