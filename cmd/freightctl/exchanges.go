package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type exchangeOptions struct {
	DSN, Token, Tenant, Partner, Storage    string
	Input, Key, ID, Endpoint, After, Output string
	Limit                                   int
	MaxFile                                 int64
	Settings                                custody.ExchangeSettings
}

func runExchanges(ctx context.Context, command string, o exchangeOptions, output io.Writer) error {
	service := &custody.Service{MaxFile: o.MaxFile, Exchanges: o.Settings}
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		return err
	}
	var registration *store.ExchangeEndpointCommand
	var offer *store.ExchangeRequest
	switch command {
	case "exchange-endpoint-command", "exchange-offer":
		if !store.ValidBrowserOperationKey(o.Key) {
			return store.ErrExchangeInput
		}
		maximum := int64(16 << 10)
		if command == "exchange-endpoint-command" {
			maximum = 24 << 10
		}
		// Request references are protected regular files, never symlinks or stdin.
		// Clear the owned bounded buffer even though credentials are not allowed
		// in the exchange schema.
		input, err := secure.ReadSecret(o.Input, maximum)
		if err != nil {
			return errors.New("exchange request must be a protected bounded regular file")
		}
		if command == "exchange-endpoint-command" {
			registration, err = store.DecodeExchangeEndpointCommand(input.Bytes, limits)
		} else {
			offer, _, _, err = store.DecodeExchangeRequest(input.Bytes, limits)
		}
		input.Close()
		if err != nil {
			return err
		}
	case "exchange-incoming":
		if !store.ValidID(o.Endpoint) || o.After != "" && !store.ValidID(o.After) || o.Limit < 1 || o.Limit > 100 {
			return store.ErrExchangeInput
		}
	case "exchange-inspect", "exchange-download":
		if !store.ValidID(o.ID) {
			return store.ErrExchangeInput
		}
		if command == "exchange-download" {
			if o.Output == "" {
				return store.ErrExchangeInput
			}
			if _, err := os.Lstat(o.Output); !errors.Is(err, os.ErrNotExist) {
				return errors.New("exchange output must be a new file")
			}
		}
	default:
		return store.ErrExchangeInput
	}
	if !store.ValidID(o.Tenant) || !store.ValidID(o.Partner) {
		return store.ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	credential, err := secure.ReadSecret(o.Token, 64)
	if err != nil {
		return err
	}
	if len(credential.Bytes) != 64 {
		credential.Close()
		return store.ErrExchangeInput
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(credential.Bytes)}
	credential.Close()
	db, err := store.Open(ctx, o.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	service.DB = db
	if command == "exchange-offer" || command == "exchange-download" {
		disk, err := custody.OpenExisting(o.Storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		service.Disk = disk
	}
	var result any
	switch command {
	case "exchange-endpoint-command":
		result, err = db.RegisterExchangeEndpoint(ctx, scope, o.Key, *registration, limits, o.Settings.MaxEndpoints)
	case "exchange-offer":
		result, err = service.OfferExchange(ctx, scope, o.Key, *offer)
	case "exchange-incoming":
		result, err = db.IncomingExchanges(ctx, scope, o.Endpoint, o.After, o.Limit, limits)
	case "exchange-inspect":
		result, err = service.InspectExchange(ctx, scope, o.ID)
	case "exchange-download":
		var file *store.File
		var reader *custody.RevisionReader
		file, reader, err = service.OpenExchangeReader(ctx, scope, o.ID)
		if err != nil {
			return err
		}
		defer reader.Close()
		if err = writeExchangeBytes(ctx, o.Output, file.Size, file.SHA256, io.NewSectionReader(reader, 0, file.Size)); err != nil {
			return err
		}
		result = struct {
			ID       string `json:"exchange_id"`
			File     string `json:"file_revision_id"`
			Size     int64  `json:"size_bytes"`
			Digest   string `json:"sha256"`
			Output   string `json:"output"`
			Evidence string `json:"evidence"`
		}{o.ID, file.ID, file.Size, file.SHA256, o.Output, "local-file-verified-and-synced"}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(result)
}

type exchangeContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r exchangeContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

// Publish only complete verified bytes, without replacing any existing output.
// A failure after Link may leave a complete file whose directory sync is unknown;
// retry must inspect that file, never truncate it or claim persistence succeeded.
func writeExchangeBytes(ctx context.Context, path string, size int64, digest string, source io.Reader) error {
	if path == "" || size < 0 || len(digest) != 64 || source == nil {
		return store.ErrExchangeInput
	}
	directory := filepath.Dir(path)
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("cannot pin output directory: %w", store.ErrIsolation)
	}
	defer root.Close()
	parent, err := root.Stat(".")
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("output directory must be private: %w", store.ErrIsolation)
	}
	stageName := ".freightctl-exchange-" + secure.NewID()
	stage, err := root.OpenFile(stageName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("cannot stage exchange bytes in output directory")
	}
	defer root.Remove(stageName)
	defer stage.Close()
	info, err := stage.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		// A platform/filesystem that cannot establish private staging must fail
		// before receiving bytes. POSIX mode support does not qualify Windows ACLs.
		return fmt.Errorf("private output staging unavailable: %w", store.ErrIsolation)
	}
	hash := secure.NewDigest()
	reader := exchangeContextReader{ctx, source}
	count, err := io.CopyBuffer(io.MultiWriter(stage, hash), io.LimitReader(reader, size), make([]byte, 256<<10))
	if err != nil {
		return err
	}
	var probe [1]byte
	n, end := reader.Read(probe[:])
	if count != size || n != 0 || end != io.EOF || fmt.Sprintf("%x", hash.Sum(nil)) != digest {
		return custody.ErrIntegrity
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = stage.Chmod(0400); err != nil {
		return err
	}
	if err = stage.Sync(); err != nil {
		return err
	}
	if err = stage.Close(); err != nil {
		return err
	}
	currentParent, err := os.Stat(directory)
	if err != nil || !os.SameFile(parent, currentParent) {
		return fmt.Errorf("output directory changed: %w", store.ErrIsolation)
	}
	if err = root.Link(stageName, filepath.Base(path)); err != nil {
		return errors.New("cannot publish exchange output without overwriting; verify new path and hard-link support")
	}
	if err = root.Remove(stageName); err != nil {
		return errors.New("verified exchange file exists; staging cleanup failed, inspect before retry")
	}
	dir, err := root.Open(".")
	if err != nil {
		return errors.New("verified exchange file exists; output directory sync unproven, inspect before retry")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("verified exchange file exists; output directory sync unproven, inspect before retry")
	}
	return nil
}
