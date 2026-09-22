//go:build acc

// TestAccBackendsAgree creates one object of each class through the LDAP
// backend, reads it back through both backends, and requires the models to be
// identical.
//
// This is the only test that checks the promise the design rests on against
// the other side, rather than against an expectation of it. The conformance
// suite proves each backend satisfies the contract; it cannot prove they
// agree, because it never compares them.
//
// It is gated on AD_ACC_DIFFERENTIAL=1 so it never runs by accident, and needs
// a reachable domain controller plus a Windows host with RSAT:
//
//	AD_ACC_DIFFERENTIAL=1
//	AD_ACC_LDAP_SERVER   e.g. s-server1.corp.local
//	AD_ACC_LDAP_CA_FILE  the CA that signed the DC certificate
//	AD_ACC_CONTAINER     an OU this run owns
//	AD_ACC_SSH_HOST      the Windows host RSAT runs on
//	AD_ACC_SSH_USER, AD_ACC_SSH_KEY_PATH
//	AD_ACC_USERNAME, AD_ACC_PASSWORD  the domain credential the cmdlets use
//	KRB5_CONFIG, KRB5CCNAME           a TGT that can reach the DC
//
// The PowerShell side reaches RSAT over SSH rather than WinRM. Both are
// equivalent for this comparison — the dialect and the cmdlets are the same
// either way — and SSH is what this lab has: see LAB.md, "The WinRM/PSRP cells
// are blocked on missing lab fixtures".
package adldap_test

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	adpwsh "github.com/nemethhh/go-adpwsh"
	pwshssh "github.com/nemethhh/go-adpwsh/transport/ssh"
)

func accEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set", name)
	}
	return v
}

// accLDAPDirectory is the native backend: LDAPS straight to the DC.
func accLDAPDirectory(t *testing.T) adcore.Directory {
	t.Helper()
	c, err := adldap.New(context.Background(), adldap.Config{
		Server:            accEnv(t, "AD_ACC_LDAP_SERVER"),
		TLS:               adldap.TLSLDAPS,
		CACertificateFile: os.Getenv("AD_ACC_LDAP_CA_FILE"),
		Kerberos: &adldap.KerberosAuth{
			CCachePath:   strings.TrimPrefix(os.Getenv("KRB5CCNAME"), "FILE:"),
			Krb5ConfPath: os.Getenv("KRB5_CONFIG"),
		},
	})
	if err != nil {
		t.Fatalf("adldap.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.Directory()
}

// accPwshDirectory is the incumbent: the ActiveDirectory module, reached over
// SSH to a Windows host. A key-based SSH session lands as a local account with
// no delegatable domain token, so the cmdlets need an explicit credential —
// the same double hop the ssh acceptance cells document.
func accPwshDirectory(t *testing.T) adcore.Directory {
	t.Helper()
	tr, err := pwshssh.New(pwshssh.Config{
		Host:           accEnv(t, "AD_ACC_SSH_HOST"),
		User:           accEnv(t, "AD_ACC_SSH_USER"),
		PrivateKeyPath: accEnv(t, "AD_ACC_SSH_KEY_PATH"),
		KnownHostsFile: os.Getenv("AD_ACC_SSH_KNOWN_HOSTS"),
		// The lab's host keys are not pinned anywhere this test can read, and
		// the comparison is of decoded models, not of transport security.
		InsecureIgnoreHostKey: os.Getenv("AD_ACC_SSH_KNOWN_HOSTS") == "",
		Timeout:               120 * time.Second,
		PwshPath:              os.Getenv("AD_ACC_PWSH_PATH"),
	})
	if err != nil {
		t.Fatalf("ssh.New: %v", err)
	}
	c, err := adpwsh.New(context.Background(), adpwsh.Config{
		Transport: tr,
		Server:    accEnv(t, "AD_ACC_LDAP_SERVER"),
		Credential: &adpwsh.Credential{
			Username: accEnv(t, "AD_ACC_USERNAME"),
			Password: adpwsh.NewSecret(accEnv(t, "AD_ACC_PASSWORD")),
		},
	})
	if err != nil {
		t.Fatalf("adpwsh.New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.Directory()
}

func accContainer(t *testing.T) string { return accEnv(t, "AD_ACC_CONTAINER") }

func TestAccBackendsAgree(t *testing.T) {
	if os.Getenv("AD_ACC_DIFFERENTIAL") != "1" {
		t.Skip("AD_ACC_DIFFERENTIAL=1 not set")
	}
	ctx := context.Background()
	ldap := accLDAPDirectory(t)
	pwsh := accPwshDirectory(t)

	container := accContainer(t)

	t.Run("ou", func(t *testing.T) {
		created, err := ldap.OU.Create(ctx, adcore.OUSpec{
			Name: "diff-ou", Container: container,
			Description: adcore.String("differential"),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() {
			_ = ldap.OU.Delete(ctx, adcore.ByGUID(created.GUID), adcore.DeleteOptions{Unprotect: true})
		})

		a, err := ldap.OU.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("ldap Get: %v", err)
		}
		b, err := pwsh.OU.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("pwsh Get: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("the backends disagree:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})

	t.Run("group", func(t *testing.T) {
		created, err := ldap.Group.Create(ctx, adcore.GroupSpec{
			Name: "diff-group", SamAccountName: "diff-group", Container: container,
			Scope: adcore.GroupScopeGlobal, Category: adcore.GroupCategorySecurity,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = ldap.Group.Delete(ctx, adcore.ByGUID(created.GUID)) })

		a, err := ldap.Group.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("ldap Get: %v", err)
		}
		b, err := pwsh.Group.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("pwsh Get: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("the backends disagree:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})

	t.Run("user", func(t *testing.T) {
		created, err := ldap.User.Create(ctx, adcore.UserSpec{
			SamAccountName: "diff-user", Container: container,
			Description: adcore.String("differential"),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = ldap.User.Delete(ctx, adcore.ByGUID(created.GUID)) })

		a, err := ldap.User.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("ldap Get: %v", err)
		}
		b, err := pwsh.User.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("pwsh Get: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("the backends disagree:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})

	t.Run("computer", func(t *testing.T) {
		created, err := ldap.Computer.Create(ctx, adcore.ComputerSpec{
			Name: "DIFFPC", SamAccountName: "DIFFPC", Container: container,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = ldap.Computer.Delete(ctx, adcore.ByGUID(created.GUID)) })

		a, err := ldap.Computer.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("ldap Get: %v", err)
		}
		b, err := pwsh.Computer.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("pwsh Get: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("the backends disagree:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})

	t.Run("gmsa", func(t *testing.T) {
		created, err := ldap.ServiceAccount.Create(ctx, adcore.GMSASpec{
			Name: "diff-gmsa", SamAccountName: "diff-gmsa", Container: container,
			DNSHostName: adcore.String("diff-gmsa." + strings.ToLower(domainOf(container))),
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		t.Cleanup(func() { _ = ldap.ServiceAccount.Delete(ctx, adcore.ByGUID(created.GUID)) })

		a, err := ldap.ServiceAccount.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("ldap Get: %v", err)
		}
		b, err := pwsh.ServiceAccount.Get(ctx, adcore.ByGUID(created.GUID))
		if err != nil {
			t.Fatalf("pwsh Get: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Errorf("the backends disagree:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})

	t.Run("acl", func(t *testing.T) {
		ou, err := ldap.OU.Create(ctx, adcore.OUSpec{Name: "diff-acl", Container: container})
		if err != nil {
			t.Fatalf("Create OU: %v", err)
		}
		t.Cleanup(func() {
			_ = ldap.OU.Delete(ctx, adcore.ByGUID(ou.GUID), adcore.DeleteOptions{Unprotect: true})
		})

		a, err := ldap.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
		if err != nil {
			t.Fatalf("ldap ACL.Get: %v", err)
		}
		b, err := pwsh.ACL.Get(ctx, adcore.ByGUID(ou.GUID))
		if err != nil {
			t.Fatalf("pwsh ACL.Get: %v", err)
		}
		// ACE order is not meaningful, so compare on the canonical key set —
		// the same comparison drift detection uses. A DeepEqual here would
		// fail on an ordering difference that means nothing.
		if !sameACESets(a, b) {
			t.Errorf("the backends disagree on the DACL:\n ldap: %+v\n pwsh: %+v", a, b)
		}
	})
}

// domainOf assembles the DNS domain from a DN's DC components, so a gMSA's
// mandatory dNSHostName follows whichever domain the run was pointed at.
func domainOf(dn string) string {
	var parts []string
	for _, c := range strings.Split(dn, ",") {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(strings.ToUpper(c), "DC=") {
			parts = append(parts, c[3:])
		}
	}
	return strings.Join(parts, ".")
}

func sameACESets(a, b []adcore.ACE) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, x := range a {
		seen[adcore.CanonicalACEKey(x)]++
	}
	for _, y := range b {
		k := adcore.CanonicalACEKey(y)
		seen[k]--
		if seen[k] < 0 {
			return false
		}
	}
	return true
}
