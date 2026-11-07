package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/ctlplne/freightctl/internal/vpath"
)

func TestNamespacePropertiesCLIRejectsAmbiguousPathBeforeCredentialOrDatabase(t *testing.T) {
	for _, path := range []string{"/one/../two", "/.freightctl/receipt", "/e\u0301.txt", "relative", ""} {
		err := run([]string{"namespace-properties", "-path", path, "-token-file", filepath.Join(t.TempDir(), "NEVER_OPEN_CREDENTIAL"), "-dsn-file", filepath.Join(t.TempDir(), "NEVER_OPEN_DATABASE")})
		if !errors.Is(err, vpath.ErrPath) {
			t.Fatal("explicit property read did not reject its selector before credential/database access", err)
		}
	}
}
