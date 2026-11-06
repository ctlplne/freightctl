package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestReceivedCopyCLIRefusesExtraAuthorityBeforeCredentialAndDatabase(t *testing.T) {
	p := filepath.Join(t.TempDir(), "copy.json")
	if err := os.WriteFile(p, []byte(`{"exchange_id":"11111111-1111-4111-8111-111111111111","virtual_path":"/new.dat","overwrite":true,"execute":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	o := exchangeOptions{Input: p, Key: "copy-stable", MaxFile: 1024, MaxStored: 4096, NamespaceMax: 100, Settings: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxEndpoints: 16, MaxOpenViews: 128}}
	err := runExchanges(context.Background(), "exchange-copy", o, io.Discard)
	if runtime.GOOS == "windows" {
		if err == nil || err.Error() != "exchange copy request must be a protected bounded regular file" {
			t.Fatal("unqualified Windows reference did not fail closed", err)
		}
	} else if !errors.Is(err, store.ErrExchangeInput) {
		t.Fatal("copy arguments reached credentials/database", err)
	}
}
