// Package ldaperr turns an LDAP failure into the same adcore.Kind the
// PowerShell backend would produce for the same condition.
//
// That is possible because AD prefixes its LDAP diagnostic messages with the
// very Win32 codes the PowerShell backend classifies on — "0000208D: NameErr:"
// is ERROR_DS_OBJ_NOT_FOUND. Parsing it out and calling adcore.ClassifyCode
// means both backends read one table, so a consumer's error handling does not
// have to know which one it is talking to.
package ldaperr

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
)

// ExtractWin32Code reads the leading hex code AD puts on its diagnostic
// messages. It requires exactly eight hex digits followed by a colon, so an
// ordinary message that merely begins with digits is not misread as a code.
func ExtractWin32Code(diagnostic string) (int, bool) {
	if len(diagnostic) < 9 || diagnostic[8] != ':' {
		return 0, false
	}
	head := diagnostic[:8]
	for i := 0; i < len(head); i++ {
		c := head[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(head, 16, 64)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// byResultCode is the fallback when the diagnostic carries no Win32 code. It
// fails closed: a code absent from this table is KindUnknown and is never
// retried.
var byResultCode = map[uint16]adcore.Kind{
	1:  adcore.KindUnknown,          // operationsError
	4:  adcore.KindTooManyResults,   // sizeLimitExceeded
	8:  adcore.KindDenied,           // strongerAuthRequired
	10: adcore.KindReferral,         // referral
	16: adcore.KindConstraint,       // noSuchAttribute
	17: adcore.KindInvalidAttribute, // undefinedAttributeType
	19: adcore.KindConstraint,       // constraintViolation
	20: adcore.KindConstraint,       // attributeOrValueExists
	21: adcore.KindInvalidAttribute, // invalidAttributeSyntax
	32: adcore.KindNotFound,         // noSuchObject
	34: adcore.KindConstraint,       // invalidDNSyntax
	49: adcore.KindDenied,           // invalidCredentials
	50: adcore.KindDenied,           // insufficientAccessRights
	51: adcore.KindTransient,        // busy
	52: adcore.KindTransient,        // unavailable
	53: adcore.KindConstraint,       // unwillingToPerform
	64: adcore.KindConstraint,       // namingViolation
	65: adcore.KindConstraint,       // objectClassViolation
	66: adcore.KindConstraint,       // notAllowedOnNonLeaf
	67: adcore.KindConstraint,       // notAllowedOnRDN
	68: adcore.KindAlreadyExists,    // entryAlreadyExists
}

// Classify normalizes an LDAP failure. A context error is KindTransport, never
// KindTransient: the request may already have reached the server, so a retry
// could duplicate a side effect.
func Classify(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
	}

	var raw *conn.RawError
	if !errors.As(err, &raw) {
		return &adcore.Error{Kind: adcore.KindTransport, Op: op, Err: err}
	}

	out := &adcore.Error{
		Op:            op,
		ServerMessage: raw.DiagnosticMessage,
		Err:           raw.Err,
	}

	if code, ok := ExtractWin32Code(raw.DiagnosticMessage); ok {
		out.Code = code
		if kind, known := adcore.ClassifyCode(code); known {
			out.Kind = kind
			return annotate(out, raw)
		}
	}
	if kind, known := byResultCode[raw.ResultCode]; known {
		out.Kind = kind
		return annotate(out, raw)
	}
	out.Kind = adcore.KindUnknown
	return annotate(out, raw)
}

// bindSubStatus maps the sub-status AD appends to a failed bind's diagnostic
// as "data <hex>". Result code 49 covers every one of these, so without the
// sub-status a wrong password and a locked-out account are indistinguishable.
var bindSubStatus = []struct {
	data, explanation string
}{
	{"data 52e", "the username or password is wrong"},
	{"data 532", "the account's password has expired or must be changed"},
	{"data 773", "the account's password has expired or must be changed"},
	{"data 775", "the account is locked out"},
	{"data 530", "the account is not permitted to log on at this time"},
	{"data 531", "the account is not permitted to log on from this host"},
	{"data 533", "the account is disabled"},
	{"data 701", "the account has expired"},
}

// annotate adds the guidance a bare LDAP message does not carry.
//
// The explanation goes on ServerMessage rather than Err, for two reasons.
// adcore.Error.Error prints ServerMessage *instead of* Err when both are set,
// so an explanation put on Err is never seen. And Err carries the wrapped
// cause that errors.Is and Unwrap walk, so overwriting it would sever the
// chain. The diagnostic stays verbatim as the prefix: it is what an operator
// pastes into a search, and it is where the Win32 code lives.
func annotate(e *adcore.Error, raw *conn.RawError) error {
	if explanation := explain(raw); explanation != "" {
		e.ServerMessage = raw.DiagnosticMessage + " — " + explanation
	}
	return e
}

func explain(raw *conn.RawError) string {
	if raw.ResultCode == 8 {
		// Over TLS, strongerAuthRequired is the channel-binding policy, not
		// the signing policy. Saying "LDAP signing" here would send an
		// operator to the wrong setting.
		return "the domain controller requires channel binding for SASL binds " +
			"(LdapEnforceChannelBinding). Upstream go-ldap does not send a channel-binding " +
			"token; use a simple bind over LDAPS, or lower the policy"
	}
	for _, s := range bindSubStatus {
		if strings.Contains(raw.DiagnosticMessage, s.data) {
			return s.explanation
		}
	}
	return ""
}
