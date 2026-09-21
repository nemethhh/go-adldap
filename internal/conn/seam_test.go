package conn_test

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go-ldap is imported in exactly one package. The whole point of this seam is
// that swapping the LDAP library — for a fork with SASL sign+seal and channel
// binding, say — is a one-package change. An import anywhere else silently
// removes that property.
func TestGoLDAPIsImportedOnlyHere(t *testing.T) {
	root := filepath.Join("..", "..")
	// Asserting only "nowhere else" would pass vacuously if the adapter were
	// deleted, and a seam nothing sits behind guards nothing. The import must
	// be here, and only here.
	var foundHere bool
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		if strings.Contains(path, string(filepath.Separator)+".git") {
			return filepath.SkipDir
		}
		pkg, perr := build.ImportDir(path, 0)
		if perr != nil {
			return nil // not a Go package
		}
		rel, _ := filepath.Rel(root, path)
		for _, imp := range append(pkg.Imports, pkg.TestImports...) {
			if !strings.HasPrefix(imp, "github.com/go-ldap/") {
				continue
			}
			if rel == filepath.Join("internal", "conn") {
				foundHere = true
				continue
			}
			t.Errorf("package %s imports %s; go-ldap belongs only in internal/conn", rel, imp)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !foundHere {
		t.Error("no package imports go-ldap; internal/conn is meant to be the adapter that does")
	}
}
