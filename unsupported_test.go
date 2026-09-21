package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
)

// The classes this backend still refuses must refuse by name and by Kind, not
// by panicking on a nil interface field. This test is what makes removing a
// stub a visible change rather than a silent one.
func TestUnsupportedClassesRefuseByName(t *testing.T) {
	ctx := context.Background()
	d := newTestDirectory(t)

	_, err := d.Schema.Resolve(ctx, []adcore.SchemaRef{{Kind: adcore.RefAttribute, Name: "member"}})
	if !errors.Is(err, adcore.ErrUnsupported) {
		t.Fatalf("Schema.Resolve = %v, want ErrUnsupported", err)
	}
}
