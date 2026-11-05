package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestServeRefusesExchangeBoundsBeforeOpeningReferences(t *testing.T) {
	for _, flags := range [][]string{{"-exchange-max-lifetime", "1ns"}, {"-exchange-max-senders", "129"}, {"-exchange-max-open-views", "0"}, {"-exchange-max-endpoints", "10001"}} {
		directory := t.TempDir()
		storage := filepath.Join(directory, "must-not-create")
		args := []string{"serve", "-dsn-file", filepath.Join(directory, "missing.dsn"), "-storage", storage, "-listen", "127.0.0.1:0"}
		err := run(append(args, flags...))
		if !errors.Is(err, custody.ErrExchangeConfiguration) {
			t.Fatalf("invalid exchange bounds reached references: %v", err)
		}
		if _, err := os.Stat(storage); !os.IsNotExist(err) {
			t.Fatal("invalid profile initialized custody")
		}
	}
}
