package ldaperr_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
	"github.com/nemethhh/go-adldap/internal/ldaperr"
)

func TestExtractWin32Code(t *testing.T) {
	for _, tc := range []struct {
		diag string
		want int
		ok   bool
	}{
		{"0000208D: NameErr: DSID-03100238, problem 2001 (NO_OBJECT)", 0x208D, true},
		{"00002071: UpdErr: DSID-030F1173, problem 6005 (ENTRY_EXISTS)", 0x2071, true},
		{"00000005: SecErr: DSID-031A11F3, problem 4003 (INSUFF_ACCESS_RIGHTS)", 0x0005, true},
		{"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data 52e", 0x80090308, true},
		{"no code here", 0, false},
		{"", 0, false},
		// Eight digits with no colon is not a code; neither is a shorter run.
		{"00002071 UpdErr", 0, false},
		{"2071: UpdErr", 0, false},
	} {
		got, ok := ldaperr.ExtractWin32Code(tc.diag)
		if ok != tc.ok {
			t.Errorf("ExtractWin32Code(%q) ok = %v, want %v", tc.diag, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("ExtractWin32Code(%q) = %#x, want %#x", tc.diag, got, tc.want)
		}
	}
}

// The hex code in the diagnostic wins over the LDAP result code, because it is
// the more precise of the two and it is the same table the PowerShell backend
// uses — which is what makes the two backends agree.
func TestWin32CodeWinsOverResultCode(t *testing.T) {
	err := ldaperr.Classify("OU.Create", &conn.RawError{
		ResultCode:        68, // entryAlreadyExists
		DiagnosticMessage: "00002071: UpdErr: DSID-030F1173, problem 6005 (ENTRY_EXISTS)",
	})
	var e *adcore.Error
	if !errors.As(err, &e) {
		t.Fatalf("want an adcore.Error, got %#v", err)
	}
	if e.Kind != adcore.KindAlreadyExists {
		t.Errorf("Kind = %v, want KindAlreadyExists", e.Kind)
	}
	if e.Code != 0x2071 {
		t.Errorf("Code = %#x, want 0x2071", e.Code)
	}
	if e.Op != "OU.Create" {
		t.Errorf("Op = %q, want %q", e.Op, "OU.Create")
	}
}

// The whole point of sharing adcore's table: the same AD condition must
// produce the same Kind whichever backend saw it.
func TestAgreesWithTheSharedCodeTable(t *testing.T) {
	for _, code := range []int{0x2030, 0x2071, 0x2098, 0x200E, 0x208D, 0x202F} {
		want, ok := adcore.ClassifyCode(code)
		if !ok {
			t.Fatalf("adcore no longer knows %#x; this test is stale", code)
		}
		diag := strings.ToUpper(pad8(code)) + ": Err: DSID-0"
		err := ldaperr.Classify("X", &conn.RawError{ResultCode: 1, DiagnosticMessage: diag})
		var e *adcore.Error
		if !errors.As(err, &e) || e.Kind != want {
			t.Errorf("code %#x classified as %v, want %v (adcore's answer)", code, e.Kind, want)
		}
	}
}

func pad8(code int) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = hex[code&0xf]
		code >>= 4
	}
	return string(out)
}

func TestResultCodeFallback(t *testing.T) {
	for _, tc := range []struct {
		code uint16
		want adcore.Kind
	}{
		{32, adcore.KindNotFound},      // noSuchObject
		{68, adcore.KindAlreadyExists}, // entryAlreadyExists
		{50, adcore.KindDenied},        // insufficientAccessRights
		{19, adcore.KindConstraint},    // constraintViolation
		{53, adcore.KindConstraint},    // unwillingToPerform
		{64, adcore.KindConstraint},    // namingViolation
		{65, adcore.KindConstraint},    // objectClassViolation
		{10, adcore.KindReferral},      // referral
		{4, adcore.KindTooManyResults}, // sizeLimitExceeded
		{49, adcore.KindDenied},        // invalidCredentials
		{8, adcore.KindDenied},         // strongerAuthRequired
	} {
		err := ldaperr.Classify("X", &conn.RawError{ResultCode: tc.code, DiagnosticMessage: "no code"})
		var e *adcore.Error
		if !errors.As(err, &e) || e.Kind != tc.want {
			t.Errorf("result code %d classified as %v, want %v", tc.code, e.Kind, tc.want)
		}
	}
}

// An unrecognized condition is KindUnknown and is never retried. Guessing that
// an unknown error is transient turns a permission problem into a hang.
func TestUnknownFailsClosed(t *testing.T) {
	err := ldaperr.Classify("X", &conn.RawError{ResultCode: 9999, DiagnosticMessage: "?"})
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindUnknown {
		t.Fatalf("want KindUnknown, got %#v", err)
	}
	if e.Kind.Retryable() {
		t.Error("KindUnknown must not be retryable")
	}
}

// A cancellation is KindTransport, never KindTransient: the request may
// already have reached the DC, so a retry could duplicate a side effect.
func TestCancellationIsTransportNotTransient(t *testing.T) {
	for _, base := range []error{context.Canceled, context.DeadlineExceeded} {
		err := ldaperr.Classify("X", base)
		var e *adcore.Error
		if !errors.As(err, &e) || e.Kind != adcore.KindTransport {
			t.Fatalf("Classify(%v) = %#v, want KindTransport", base, err)
		}
		if e.Kind.Retryable() {
			t.Errorf("Classify(%v) produced a retryable Kind", base)
		}
		if !errors.Is(err, base) {
			t.Errorf("Classify(%v) lost the cause", base)
		}
	}
}

// strongerAuthRequired over TLS is the channel-binding policy. The message
// must say so, because the bare LDAP text sends operators to the wrong setting.
func TestStrongerAuthRequiredNamesChannelBinding(t *testing.T) {
	err := ldaperr.Classify("New", &conn.RawError{ResultCode: 8, DiagnosticMessage: "00002028: LdapErr: ..."})
	if !strings.Contains(err.Error(), "channel binding") {
		t.Errorf("error does not mention channel binding: %v", err)
	}
}

// The sub-status after "data" is the only thing distinguishing a wrong
// password from a locked-out account; AD returns result code 49 for both.
func TestBindSubStatusIsSpelledOut(t *testing.T) {
	for _, tc := range []struct{ data, want string }{
		{"52e", "username or password"},
		{"532", "expired"},
		{"773", "expired"},
		{"775", "locked out"},
		{"530", "not permitted"},
		{"531", "not permitted"},
	} {
		diag := "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data " + tc.data + ", v4563"
		err := ldaperr.Classify("New", &conn.RawError{ResultCode: 49, DiagnosticMessage: diag})
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("data %s: error does not say %q: %v", tc.data, tc.want, err)
		}
	}
}
