package adldap_test

import (
	"context"
	"errors"
	"testing"

	"github.com/nemethhh/go-adcore"
	adldap "github.com/nemethhh/go-adldap"
	"github.com/nemethhh/go-adldap/internal/adtest"
)

func TestNewWithAWrongPasswordIsDenied(t *testing.T) {
	srv := adtest.Start(t)
	cfg := srv.Config()
	cfg.Simple.Password = adtest.WrongPassword()

	_, err := adldap.New(context.Background(), cfg)
	var e *adcore.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *adcore.Error, got %#v", err)
	}
	if e.Kind != adcore.KindDenied {
		t.Errorf("Kind = %v, want KindDenied: the DC answered and refused the credential; nothing failed in transport", e.Kind)
	}
}

func TestNewAgainstAClosedPortIsATransportFailure(t *testing.T) {
	srv := adtest.Start(t)
	cfg := srv.Config()
	cfg.Port = 1

	_, err := adldap.New(context.Background(), cfg)
	var e *adcore.Error
	if !errors.As(err, &e) || e.Kind != adcore.KindTransport {
		t.Fatalf("want KindTransport, got %#v", err)
	}
}
