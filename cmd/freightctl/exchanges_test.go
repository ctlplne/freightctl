package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeCLIRefusesInvalidSelectorsBeforeOpeningReferences(t *testing.T) {
	for _, args := range [][]string{
		{"exchange-endpoint-list", "-exchange-after", "not-an-id"},
		{"exchange-endpoint-inspect", "-exchange-endpoint-id", "not-an-id"},
		{"exchange-incoming", "-exchange-endpoint-id", "not-an-id"},
		{"exchange-inspect", "-exchange-id", "not-an-id"},
		{"exchange-download", "-exchange-id", "not-an-id", "-output", "must-not-create"},
		{"exchange-offer", "-idempotency-key", "bad key"},
		{"exchange-endpoint-command", "-idempotency-key", "bad key"},
	} {
		if err := run(args); !errors.Is(err, store.ErrExchangeInput) {
			t.Fatalf("exchange CLI did not reject invalid input before opening references: %v", err)
		}
	}
}

func TestExchangeCLIRefusesPayloadAuthorityBeforeCredentialAndDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte(`{"approved":true,"url":"https://unapproved.invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	o := exchangeOptions{Input: path, Key: "original-key", MaxFile: 1024, Settings: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}
	for _, command := range []string{"exchange-offer", "exchange-endpoint-command"} {
		err := runExchanges(context.Background(), command, o, io.Discard)
		if runtime.GOOS == "windows" {
			// Windows protected-reference qualification is owed. Its regular-file
			// mode refusal must still happen before any credential or DB access.
			if err == nil || err.Error() != "exchange request must be a protected bounded regular file" {
				t.Fatal("Windows request reference did not fail closed", err)
			}
		} else if !errors.Is(err, store.ErrExchangeInput) {
			t.Fatal("payload authority reached credentials or database", err)
		}
	}
}

type exchangeInterruptedReader struct{ delivered bool }

func (r *exchangeInterruptedReader) Read(p []byte) (int, error) {
	if r.delivered {
		return 0, io.ErrUnexpectedEOF
	}
	r.delivered = true
	return copy(p, "partial"), nil
}

func TestExchangeDownloadPublishesOnlyCompleteVerifiedPrivateBytes(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("inert artifact bytes\n"), 16000)
	path := filepath.Join(directory, "received")
	err := writeExchangeBytes(context.Background(), path, int64(len(data)), secure.Digest(data), bytes.NewReader(data))
	if runtime.GOOS == "windows" {
		if !errors.Is(err, store.ErrIsolation) {
			t.Fatal("unsupported private staging did not refuse", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("published bytes differ", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("output is not private and read-only", err)
	}
	if err = writeExchangeBytes(context.Background(), path, 7, secure.Digest([]byte("changed")), bytes.NewBufferString("changed")); err == nil {
		t.Fatal("existing output was replaced")
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("failed retry modified output", err)
	}
	empty := filepath.Join(directory, "empty")
	if err = writeExchangeBytes(context.Background(), empty, 0, secure.Digest(nil), bytes.NewReader(nil)); err != nil {
		t.Fatal("empty exact artifact", err)
	}
}

func TestExchangeDownloadFailureNeverPublishesPartialBytes(t *testing.T) {
	for _, scenario := range []string{"short", "extra", "digest", "interrupt", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "must-not-exist")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reader io.Reader = bytes.NewBufferString("expected")
			size, digest := int64(8), secure.Digest([]byte("expected"))
			expected := custody.ErrIntegrity
			switch scenario {
			case "short":
				size++
			case "extra":
				size--
			case "digest":
				digest = secure.Digest([]byte("different"))
			case "interrupt":
				reader = &exchangeInterruptedReader{}
				expected = io.ErrUnexpectedEOF
			case "canceled":
				cancel()
				expected = context.Canceled
			}
			if runtime.GOOS == "windows" {
				expected = store.ErrIsolation
			}
			if err := writeExchangeBytes(ctx, path, size, digest, reader); !errors.Is(err, expected) {
				t.Fatal("did not observe the expected refusal before publication", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("partial output visible", err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatal("private partial staging leaked", err)
			}
		})
	}
}

func TestExchangeDownloadRefusesUnprotectedOutputDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	err := writeExchangeBytes(context.Background(), filepath.Join(directory, "received"), 5, secure.Digest([]byte("exact")), bytes.NewBufferString("exact"))
	if !errors.Is(err, store.ErrIsolation) {
		t.Fatal("output directory was not protected before staging bytes", err)
	}
}

type exchangeDirectorySwapReader struct {
	swap   func()
	source io.Reader
}

func (r *exchangeDirectorySwapReader) Read(p []byte) (int, error) {
	if r.swap != nil {
		callback := r.swap
		r.swap = nil
		callback()
	}
	return r.source.Read(p)
}

func TestExchangeDownloadDirectoryReplacementCannotSubstituteVerifiedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		err := writeExchangeBytes(context.Background(), filepath.Join(t.TempDir(), "received"), 5, secure.Digest([]byte("exact")), bytes.NewBufferString("exact"))
		if !errors.Is(err, store.ErrIsolation) {
			t.Fatal("Windows private staging did not fail closed", err)
		}
		return // Directory substitution on Windows remains owed with native ACL support.
	}
	parent := t.TempDir()
	directory, moved := filepath.Join(parent, "output"), filepath.Join(parent, "moved")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	var foreign string
	reader := &exchangeDirectorySwapReader{source: bytes.NewBufferString("exact")}
	reader.swap = func() {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 1 {
			t.Fatal("missing owned stage", err)
		}
		name := entries[0].Name()
		if err = os.Rename(directory, moved); err != nil {
			t.Fatal(err)
		}
		if err = os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		foreign = filepath.Join(directory, name)
		if err = os.WriteFile(foreign, []byte("unverified substitution"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err := writeExchangeBytes(context.Background(), filepath.Join(directory, "received"), 5, secure.Digest([]byte("exact")), reader)
	if !errors.Is(err, store.ErrIsolation) {
		t.Fatal("replaced output directory did not fail closed", err)
	}
	if _, err = os.Lstat(filepath.Join(directory, "received")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unverified replacement was published", err)
	}
	if foreignData, err := os.ReadFile(foreign); err != nil || string(foreignData) != "unverified substitution" {
		t.Fatal("cleanup touched a foreign replacement", err)
	}
	if entries, err := os.ReadDir(moved); err != nil || len(entries) != 0 {
		t.Fatal("owned partial stage not cleaned", err)
	}
}
