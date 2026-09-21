package conn

import (
	"strings"
	"testing"
)

func TestNTLMBinderDescribeHidesPassword(t *testing.T) {
	b := NTLMBinder{Domain: "CORP", Username: "svc_tf", Password: "hunter2"}
	got := b.Describe()
	if strings.Contains(got, "hunter2") {
		t.Errorf("Describe leaked the password: %q", got)
	}
	if !strings.Contains(got, "CORP") || !strings.Contains(got, "svc_tf") {
		t.Errorf("Describe should name the principal: %q", got)
	}
}
