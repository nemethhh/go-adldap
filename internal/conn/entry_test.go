package conn_test

import (
	"testing"

	"github.com/nemethhh/go-adldap/internal/conn"
)

// An LDAP attribute description is case-insensitive, and a server answers with
// the schema's own spelling rather than the one asked for. rightsGuid is the
// case that found this: asking for "rightsGUID" returns an entry keyed
// "rightsGuid", and an exact lookup reads as the object simply not having the
// attribute.
func TestEntryFirstIsCaseInsensitive(t *testing.T) {
	e := conn.Entry{Attrs: map[string][][]byte{
		"rightsGuid": {[]byte("00299570-246d-11d0-a768-00aa006e0529")},
	}}
	for _, spelling := range []string{"rightsGuid", "rightsGUID", "RIGHTSGUID", "rightsguid"} {
		if got := string(e.First(spelling)); got != "00299570-246d-11d0-a768-00aa006e0529" {
			t.Errorf("First(%q) = %q, want the value", spelling, got)
		}
	}
	if e.First("somethingElse") != nil {
		t.Error("an attribute that is genuinely absent must still read as nil")
	}
}
