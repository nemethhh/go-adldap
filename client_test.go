package adldap_test

import (
	"context"
	"testing"

	adldap "github.com/nemethhh/go-adldap"
)

func TestNewRejectsAnInvalidConfig(t *testing.T) {
	if _, err := adldap.New(context.Background(), adldap.Config{}); err == nil {
		t.Fatal("New must validate before dialling")
	}
}
