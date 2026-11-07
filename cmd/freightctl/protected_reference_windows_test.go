//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"golang.org/x/sys/windows"
)

func TestWindowsPublicDownloadPinsOutputNameAndStillVerifiesExactPrivateBytes(t *testing.T) {
	directory := privateCLIDirectory(t)
	before, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	attempted := false
	reader := &exchangeDirectorySwapReader{source: bytes.NewBufferString("exact")}
	reader.swap = func() {
		attempted = true
		err := os.Rename(directory, filepath.Join(filepath.Dir(directory), "moved"))
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatal("public root did not retain the native name pin", err)
		}
	}
	output := filepath.Join(directory, "received")
	if err = writeExchangeBytes(context.Background(), output, 5, secure.Digest([]byte("exact")), reader); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(directory)
	if err != nil || !attempted || !os.SameFile(before, after) {
		t.Fatal("public output directory changed", err)
	}
	requireSealedCLIOutput(t, output)
	body, err := os.ReadFile(output)
	if err != nil || string(body) != "exact" {
		t.Fatal("public download lost exact original bytes", err)
	}
}
