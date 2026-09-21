package adldap

import (
	"errors"

	"github.com/nemethhh/go-adcore"
)

// asError is errors.As specialized to *adcore.Error, so the classification
// checks scattered through this package read as one idea rather than as a
// generic call whose target type has to be re-read at each site.
func asError(err error, out **adcore.Error) bool { return errors.As(err, out) }
