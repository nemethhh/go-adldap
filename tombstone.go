package adldap

import (
	"context"

	"github.com/nemethhh/go-adcore"
	"github.com/nemethhh/go-adldap/internal/conn"
)

type deletedMatch struct {
	DN              string
	LastKnownParent string
}

// probeDeleted searches the Deleted Objects container.
//
// With the Recycle Bin enabled a deleted object keeps its sAMAccountName and
// blocks re-creation with an error that names nothing an operator can find.
// The show-deleted control is what makes those objects visible at all.
//
// filter must already be RFC 4515 escaped by the caller.
func (c *core) probeDeleted(ctx context.Context, filter string) ([]deletedMatch, error) {
	var out []deletedMatch
	err := c.withConn(ctx, "deleted_probe", func(cn conn.Conn) error {
		res, err := cn.Search(ctx, conn.SearchRequest{
			BaseDN:     c.dnc,
			Scope:      conn.ScopeSubtree,
			Filter:     filter,
			Attributes: []string{"distinguishedName", "lastKnownParent"},
			SizeLimit:  16,
			Controls:   []conn.Control{{OID: ControlShowDeleted, Critical: true}},
		})
		if err != nil {
			return err
		}
		for _, e := range res.Entries {
			out = append(out, deletedMatch{DN: e.DN, LastKnownParent: e.FirstString("lastKnownParent")})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// annotateAlreadyExists upgrades an already-exists error with the deleted
// object that caused it, when there is one.
//
// A probe failure is swallowed deliberately: the original error is the one the
// caller needs, and the annotation is a courtesy. Replacing a precise
// already-exists with a probe's transport failure would be a worse message.
func (c *core) annotateAlreadyExists(ctx context.Context, err error, filter string) error {
	var e *adcore.Error
	if !asError(err, &e) || e.Kind != adcore.KindAlreadyExists {
		return err
	}
	matches, probeErr := c.probeDeleted(ctx, filter)
	if probeErr != nil || len(matches) == 0 {
		return err
	}
	e.Tombstoned = true
	e.Target = matches[0].DN
	return e
}

// deletedFilter looks for a tombstone of one class under a parent. Deleted
// objects keep a mangled name — "Gone\0ADEL:<guid>" — so the probe matches on
// lastKnownParent plus a name prefix rather than on an exact name.
func deletedFilter(objectClass, name, container string) string {
	return "(&(isDeleted=TRUE)" +
		adcore.Equal("objectClass", objectClass) +
		adcore.Equal("lastKnownParent", container) +
		"(name=" + adcore.EscapeFilter(name) + "*))"
}
