package main

import (
	_ "embed"
	"testing"
)

// The release workflow runs the compiled test binaries outside the source
// tree, so the golden file is embedded instead of read from testdata/ at
// runtime. testdata/sssd-lldap.golden stays the single source.
//
//go:embed testdata/sssd-lldap.golden
var sssdLLDAPGolden string

// lldapGolden returns the embedded LLDAP sssd.conf golden and fails the test
// if it is empty, so an empty file can never make a comparison pass.
func lldapGolden(t *testing.T) string {
	t.Helper()
	if sssdLLDAPGolden == "" {
		t.Fatal("embedded testdata/sssd-lldap.golden is empty")
	}
	return sssdLLDAPGolden
}
