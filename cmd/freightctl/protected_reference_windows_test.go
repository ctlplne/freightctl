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
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"golang.org/x/sys/windows"
)

func TestWindowsActiveDownloadStagePreventsParentReplacement(t *testing.T) {
	parent := t.TempDir()
	directory, moved := filepath.Join(parent, "output"), filepath.Join(parent, "moved")
	if err := protectedfs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		t.Fatal(err)
	}
	defer parentRoot.Close()
	heldRoot, err := parentRoot.OpenRoot("output")
	if err != nil {
		t.Fatal(err)
	}
	defer heldRoot.Close()
	before, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	attempted := false
	reader := &exchangeDirectorySwapReader{source: bytes.NewBufferString("exact")}
	reader.swap = func() {
		attempted = true
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 1 {
			t.Fatal("missing active private stage", err)
		}
		if err = os.Rename(directory, moved); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Fatal("active private child did not prevent parent replacement", err)
		}
	}
	output := filepath.Join(directory, "received")
	if err = writeExchangeBytesAt(t.Context(), output, 5, secure.Digest([]byte("exact")), reader, heldRoot); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(directory)
	if err != nil || !attempted || !os.SameFile(before, after) {
		t.Fatal("active-stage refusal changed original parent", err)
	}
	if _, err = os.Lstat(moved); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active stage's parent was moved", err)
	}
	requireSealedCLIOutput(t, output)
	if body, err := os.ReadFile(output); err != nil || string(body) != "exact" {
		t.Fatal("active-stage refusal lost exact sealed bytes", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 1 || entries[0].Name() != "received" {
		t.Fatal("active-stage refusal left partial or foreign bytes", err)
	}
}

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
