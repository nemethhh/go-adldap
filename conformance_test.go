package adldap_test

import (
	"testing"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adcore/adcoretest"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

// The LDAP backend must satisfy every guarantee adcore states, asserted by the
// same suite go-adpwsh runs. This is what keeps the two from drifting.
//
// It runs against the in-memory conn rather than the gldap harness because the
// suite exercises rename and move, which gldap cannot serve — see
// adtest.MemServer. Everything under test here is the real implementation:
// ou.go, search.go, exec.go and the pool.
func TestLDAPDirectoryConformance(t *testing.T) {
	adcoretest.RunDirectorySuite(t, func(t *testing.T) adcore.Directory {
		return adtest.StartMemory(t).Directory(t)
	})
}
