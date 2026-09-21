package adldap

import (
	"context"
	"fmt"

	"github.com/nemethhh/go-adcore"
)

// The object classes this backend does not implement yet.
//
// These were nil interface fields on the Directory, on the reasoning that a
// nil fails loudly at the first call while a stub is dead code nobody notices
// shipping. The lab disproved it: a nil field does not fail loudly, it panics
// with a nil pointer dereference inside the consumer, which took an entire
// acceptance run down with it and named neither the class nor the reason.
//
// A stub that says exactly what is missing is the honest version of the same
// intent. It is not dead code — it is the documented behaviour of this
// backend, and it is covered by tests.
func unsupported(op, what string) error {
	return &adcore.Error{
		Kind: adcore.KindUnsupported, Op: op,
		Err: fmt.Errorf("the ldap connection does not implement %s; use one of the "+
			"PowerShell connections (local, ssh or winrm) for these", what),
	}
}

const (
	whatServiceAccount = "group Managed Service Accounts"
	whatComputer       = "computer accounts"
	whatACL            = "access control entries"
	whatSchema         = "schema resolution"
)

type unsupportedServiceAccount struct{}

var _ adcore.ServiceAccountDirectory = unsupportedServiceAccount{}

func (unsupportedServiceAccount) Create(context.Context, adcore.GMSASpec) (*adcore.GMSA, error) {
	return nil, unsupported("ServiceAccount.Create", whatServiceAccount)
}

func (unsupportedServiceAccount) Get(context.Context, adcore.Identity) (*adcore.GMSA, error) {
	return nil, unsupported("ServiceAccount.Get", whatServiceAccount)
}

func (unsupportedServiceAccount) Search(context.Context, adcore.Query) ([]adcore.GMSA, error) {
	return nil, unsupported("ServiceAccount.Search", whatServiceAccount)
}

func (unsupportedServiceAccount) Update(context.Context, adcore.Identity, adcore.GMSASpec) (*adcore.GMSA, error) {
	return nil, unsupported("ServiceAccount.Update", whatServiceAccount)
}

func (unsupportedServiceAccount) Delete(context.Context, adcore.Identity) error {
	return unsupported("ServiceAccount.Delete", whatServiceAccount)
}

type unsupportedComputer struct{}

var _ adcore.ComputerDirectory = unsupportedComputer{}

func (unsupportedComputer) Create(context.Context, adcore.ComputerSpec) (*adcore.Computer, error) {
	return nil, unsupported("Computer.Create", whatComputer)
}

func (unsupportedComputer) Get(context.Context, adcore.Identity) (*adcore.Computer, error) {
	return nil, unsupported("Computer.Get", whatComputer)
}

func (unsupportedComputer) Search(context.Context, adcore.Query) ([]adcore.Computer, error) {
	return nil, unsupported("Computer.Search", whatComputer)
}

func (unsupportedComputer) Update(context.Context, adcore.Identity, adcore.ComputerSpec) (*adcore.Computer, error) {
	return nil, unsupported("Computer.Update", whatComputer)
}

func (unsupportedComputer) Delete(context.Context, adcore.Identity) error {
	return unsupported("Computer.Delete", whatComputer)
}

type unsupportedACL struct{}

var _ adcore.ACLDirectory = unsupportedACL{}

func (unsupportedACL) Get(context.Context, adcore.Identity) ([]adcore.ACE, error) {
	return nil, unsupported("ACL.Get", whatACL)
}

func (unsupportedACL) Grant(context.Context, adcore.Identity, []adcore.ACE) error {
	return unsupported("ACL.Grant", whatACL)
}

func (unsupportedACL) Revoke(context.Context, adcore.Identity, []adcore.ACE) error {
	return unsupported("ACL.Revoke", whatACL)
}

type unsupportedSchema struct{}

var _ adcore.SchemaDirectory = unsupportedSchema{}

func (unsupportedSchema) Resolve(context.Context, []adcore.SchemaRef) (map[adcore.SchemaRef]string, error) {
	return nil, unsupported("Schema.Resolve", whatSchema)
}
