package conn

import (
	"strings"
	"testing"
)

func TestSimpleBinderDescribeHidesPassword(t *testing.T) {
	b := SimpleBinder{Username: `corp\svc_tf`, Password: "hunter2"}
	got := b.Describe()
	if got == "" {
		t.Fatal("Describe must say something; it is what a log line records")
	}
	if strings.Contains(got, "hunter2") {
		t.Errorf("Describe leaked the password: %q", got)
	}
	if !strings.Contains(got, `corp\svc_tf`) {
		t.Errorf("Describe should name the principal: %q", got)
	}
}

// An empty password is an unauthenticated bind: AD accepts it and hands back
// an anonymous session with almost no rights, so the failure surfaces much
// later as an unexplained access-denied on the first write.
func TestSimpleBinderRefusesEmptyPassword(t *testing.T) {
	err := SimpleBinder{Username: "svc_tf"}.Bind(t.Context(), &goldapConn{})
	if err == nil {
		t.Fatal("an empty password must be refused before the bind is attempted")
	}
	if !strings.Contains(err.Error(), "anonymous") {
		t.Errorf("the error should say what an empty password actually does: %v", err)
	}
}
