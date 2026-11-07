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
	"github.com/ctlplne/freightctl/internal/durablefs"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type exchangeOptions struct {
	DSN, Token, Tenant, Partner, Storage    string
	Input, Key, ID, Endpoint, After, Output string
	Limit                                   int
	MaxFile, MaxStored                      int64
	NamespaceMax                            int
	Settings                                custody.ExchangeSettings
}

func runExchanges(ctx context.Context, command string, o exchangeOptions, output io.Writer) error {
	service := &custody.Service{MaxFile: o.MaxFile, MaxStored: o.MaxStored, NamespaceMaxEntries: o.NamespaceMax, Exchanges: o.Settings}
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		return err
	}
	var registration *store.ExchangeEndpointCommand
	var offer *store.ExchangeRequest
	var closure *store.ExchangeClosureCommand
	var ingress custody.IngressDescriptorRequest
	var trace store.ExchangeTraceRequest
	var copyRequest store.ExchangeCopyRequest
	switch command {
	case "exchange-copy":
		if !store.ValidBrowserOperationKey(o.Key) {
			return store.ErrExchangeInput
		}
		input, err := secure.ReadSecret(o.Input, 16<<10)
		if err != nil {
			return errors.New("exchange copy request must be a protected bounded regular file")
		}
		err = workflow.Decode(input.Bytes, &copyRequest)
		input.Close()
		if err != nil {
			return store.ErrExchangeInput
		}
		if err = store.ValidateExchangeCopy(copyRequest, o.MaxFile); err != nil {
			return err
		}
		if o.MaxStored < o.MaxFile || o.NamespaceMax < 1 {
			return store.ErrExchangeInput
		}
	case "exchange-trace":
		input, err := secure.ReadSecret(o.Input, 16<<10)
		if err != nil {
			return errors.New("exchange evidence request must be a protected bounded regular file")
		}
		err = workflow.Decode(input.Bytes, &trace)
		input.Close()
		if err != nil {
			return err
		}
		if err = store.ValidateExchangeTraceRequest(trace); err != nil {
			return err
		}
	case "exchange-ingress-descriptor":
		input, err := secure.ReadSecret(o.Input, 16<<10)
		if err != nil {
			return errors.New("ingress metadata must be a protected bounded regular file")
		}
		err = workflow.Decode(input.Bytes, &ingress)
		input.Close()
		if err != nil {
			return err
		}
	case "exchange-endpoint-command", "exchange-offer", "exchange-close":
		if !store.ValidBrowserOperationKey(o.Key) {
			return store.ErrExchangeInput
		}
		maximum := int64(16 << 10)
		if command == "exchange-endpoint-command" {
			maximum = 24 << 10
		} else if command == "exchange-close" {
			maximum = 4096
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
		} else if command == "exchange-close" {
			closure, err = store.DecodeExchangeClosure(input.Bytes)
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
	case "exchange-endpoint-list", "exchange-outgoing":
		if o.After != "" && !store.ValidID(o.After) || o.Limit < 1 || o.Limit > 100 {
			return store.ErrExchangeInput
		}
	case "exchange-endpoint-inspect":
		if !store.ValidID(o.Endpoint) {
			return store.ErrExchangeInput
		}
	case "exchange-inspect", "exchange-download", "exchange-source-inspect", "exchange-outgoing-inspect":
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
	if command == "exchange-offer" || command == "exchange-download" || command == "exchange-copy" {
		disk, err := custody.OpenExisting(o.Storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		service.Disk = disk
	}
	var result any
	switch command {
	case "exchange-copy":
		result, err = service.CopyReceivedExchange(ctx, scope, o.Key, copyRequest)
	case "exchange-trace":
		result, err = service.TraceExchange(ctx, scope, trace)
	case "exchange-ingress-descriptor":
		result, err = service.PrepareArtifactIngress(ctx, scope, ingress)
	case "exchange-close":
		result, err = db.CloseExchange(ctx, scope, o.Key, *closure)
	case "exchange-endpoint-command":
		result, err = db.RegisterExchangeEndpoint(ctx, scope, o.Key, *registration, limits, o.Settings.MaxEndpoints)
	case "exchange-endpoint-list":
		result, err = db.ExchangeEndpoints(ctx, scope, o.After, o.Limit)
	case "exchange-endpoint-inspect":
		result, err = db.ExchangeEndpoint(ctx, scope, o.Endpoint)
	case "exchange-offer":
		result, err = service.OfferExchange(ctx, scope, o.Key, *offer)
	case "exchange-incoming":
		result, err = db.IncomingExchanges(ctx, scope, o.Endpoint, o.After, o.Limit, limits)
	case "exchange-inspect":
		result, err = service.InspectExchange(ctx, scope, o.ID)
	case "exchange-outgoing":
		result, err = db.OutgoingExchanges(ctx, scope, o.After, o.Limit)
	case "exchange-outgoing-inspect":
		result, err = db.OutgoingExchange(ctx, scope, o.ID)
	case "exchange-source-inspect":
		result, err = service.InspectExchangeSource(ctx, scope, o.ID)
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
	directoryHandle, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("cannot inspect held output directory: %w", store.ErrIsolation)
	}
	parent, statErr := directoryHandle.Stat()
	if err = errors.Join(statErr, protectedfs.ValidateDirectory(directoryHandle), directoryHandle.Close()); err != nil {
		return fmt.Errorf("output directory must be private: %w", store.ErrIsolation)
	}
	stageName := ".freightctl-exchange-" + secure.NewID()
	stage, err := protectedfs.CreateAt(root, stageName)
	if err != nil {
		return errors.New("cannot stage exchange bytes in output directory")
	}
	defer root.Remove(stageName)
	defer stage.Close()
	if err = protectedfs.ValidateFile(stage); err != nil {
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
	if err = protectedfs.SealReadOnly(stage); err != nil {
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
	if err = durablefs.SyncDirectory(dir); err != nil {
		return errors.New("verified exchange file exists; output directory sync unproven, inspect before retry")
	}
	return nil
}
