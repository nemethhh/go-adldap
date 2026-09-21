package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestNewRejectsAnInvalidConfig(t *testing.T) {
	if _, err := adldap.New(context.Background(), adldap.Config{}); err == nil {
		t.Fatal("New must validate before dialling")
	}
}

// The classes this backend has not implemented must answer with a Kind, not a
// nil dereference. A nil interface field panics inside the consumer, which on
// the lab aborted an entire acceptance run and named neither the class nor the
// reason.
func TestUnimplementedClassesReportUnsupported(t *testing.T) {
	d := adtest.StartMemory(t).Directory(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"Computer.Create":       func() error { _, err := d.Computer.Create(ctx, adcore.ComputerSpec{}); return err },
		"Computer.Get":          func() error { _, err := d.Computer.Get(ctx, adcore.ByGUID("x")); return err },
		"ServiceAccount.Create": func() error { _, err := d.ServiceAccount.Create(ctx, adcore.GMSASpec{}); return err },
		"ACL.Get":               func() error { _, err := d.ACL.Get(ctx, adcore.ByGUID("x")); return err },
		"ACL.Grant":             func() error { return d.ACL.Grant(ctx, adcore.ByGUID("x"), nil) },
		"Schema.Resolve":        func() error { _, err := d.Schema.Resolve(ctx, nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			err := call()
			var e *adcore.Error
			if !errors.As(err, &e) || e.Kind != adcore.KindUnsupported {
				t.Fatalf("want KindUnsupported, got %#v", err)
			}
		})
	}
}
