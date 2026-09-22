package conn_test

import (
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// go-ldap and the Kerberos library are imported in exactly one package. The
// whole point of this seam is that swapping either — for a fork, or for a
// maintained successor — is a one-package change. An import anywhere else
// silently removes that property.
func TestLDAPAndKerberosAreImportedOnlyHere(t *testing.T) {
	root := filepath.Join("..", "..")
	// Asserting only "nowhere else" would pass vacuously if the adapter were
	// deleted, and a seam nothing sits behind guards nothing. The import must
	// be here, and only here. Two independent bools, not one combined: a
	// single foundHere only proves at least one library is imported in
	// internal/conn, so deleting either adapter alone would pass silently.
	const ldapPrefix = "github.com/go-ldap/"
	const kerberosPrefix = "github.com/oiweiwei/gokrb5.fork/"
	var foundLDAPHere, foundKerberosHere bool
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
			var here *bool
			switch {
			case strings.HasPrefix(imp, ldapPrefix):
				here = &foundLDAPHere
			case strings.HasPrefix(imp, kerberosPrefix):
				here = &foundKerberosHere
			default:
				continue
			}
			if rel == filepath.Join("internal", "conn") {
				*here = true
				continue
			}
			t.Errorf("package %s imports %s; go-ldap and the Kerberos library belong only in internal/conn", rel, imp)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !foundLDAPHere {
		t.Error("no package imports go-ldap; internal/conn is meant to be the adapter that does")
	}
	if !foundKerberosHere {
		t.Error("no package imports the Kerberos library; internal/conn is meant to be the adapter that does")
	}
}
