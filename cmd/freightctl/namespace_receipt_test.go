package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNamespaceReceiptCLIRequiresOriginalKeyBeforeCredentialOrDatabase(t *testing.T) {
	for _, key := range []string{"", "space key", "../path", strings.Repeat("x", 129)} {
		err := run([]string{"namespace-receipt", "-idempotency-key", key, "-token-file", filepath.Join(t.TempDir(), "NEVER_OPEN_CREDENTIAL"), "-dsn-file", filepath.Join(t.TempDir(), "NEVER_OPEN_DATABASE")})
		if err == nil || err.Error() != "receipt requires the original namespace command key" {
			t.Fatal("receipt CLI lacks original-key selection before resources", err)
		}
	}
}
