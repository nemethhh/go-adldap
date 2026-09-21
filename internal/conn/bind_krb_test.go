package conn

import (
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/flags"
)

// The AP-REQ must request mutual authentication. go-ldap's own GSSAPIBind
// helper sends no AP options while asking for ContextFlagMutual in the
// checksum, and Active Directory refuses that inconsistency with
// "AcceptSecurityContext error, data 57" — an ERROR_INVALID_PARAMETER that
// reads like a bad credential when the ticket is in fact perfect.
//
// There is no KDC in CI, so this guards the one thing that made the bind
// impossible: the option going missing again.
func TestAPOptionsRequestMutualAuthentication(t *testing.T) {
	got := apOptions()
	if len(got) == 0 {
		t.Fatal("no AP options; a bind with none is refused by AD with data 57")
	}
	for _, o := range got {
		if o == flags.APOptionMutualRequired {
			return
		}
	}
	t.Errorf("apOptions() = %v, want it to contain APOptionMutualRequired (%d)", got, flags.APOptionMutualRequired)
}
