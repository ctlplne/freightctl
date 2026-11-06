package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestAuditHistoryCLIRejectsPayloadAuthorityBeforeCredentialAndDatabase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(p, []byte(`{"limit":10,"include_payload":true,"sql":"untrusted"}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := runAuditHistory(context.Background(), auditHistoryOptions{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "22222222-2222-4222-8222-222222222222", Input: p}, io.Discard)
	if runtime.GOOS == "windows" {
		if err == nil || err.Error() != "audit search must be a protected bounded regular file" {
			t.Fatal("unqualified Windows reference did not fail closed", err)
		}
	} else if !errors.Is(err, store.ErrExchangeInput) {
		t.Fatal("history selectors reached credential or database", err)
	}
}
