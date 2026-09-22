package ldaperr_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/ldaperr"
)

// strongerAuthRequired over TLS is the channel-binding policy. The message
// must name the setting, because the server's does not — but it must no
// longer claim the library cannot send a token, which is now true only of
// NTLM.
func TestChannelBindingRefusalNamesTheSettingAndTheWorkingMechanisms(t *testing.T) {
	err := ldaperr.Classify("Bind", &conn.RawError{
		ResultCode:        8,
		DiagnosticMessage: "80090346: LdapErr: DSID-0C09062B, comment: AcceptSecurityContext error, data 80090346",
	})

	var e *adcore.Error
	if !errors.As(err, &e) {
		t.Fatalf("Classify returned %T, want *adcore.Error", err)
	}
	msg := e.ServerMessage

	if !strings.Contains(msg, "LdapEnforceChannelBinding") {
		t.Errorf("message should name the setting: %q", msg)
	}
	if strings.Contains(msg, "go-ldap does not send") {
		t.Errorf("message still claims no token is sent; Kerberos now sends one: %q", msg)
	}
	if !strings.Contains(msg, "NTLM") {
		t.Errorf("message should say NTLM is the mechanism that cannot comply: %q", msg)
	}
}
