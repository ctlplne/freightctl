package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type configurationExporter func(*workflow.Service, context.Context, store.Scope, workflow.Reference, io.Writer) (*workflow.PortableExportReceipt, error)

func preparePortableOutputPolicy(service *workflow.Service, ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
	checkService := checks.Service{Custody: service.Custody}
	return checkService.PreparePortableOutputPolicy(ctx, scope, ref, output)
}

func preparePortableIntakePolicy(service *workflow.Service, ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
	checkService := checks.Service{Custody: service.Custody}
	return checkService.PreparePortableIntakePolicy(ctx, scope, ref, output)
}

func portablePartnerExporter(event string) configurationExporter {
	return func(service *workflow.Service, ctx context.Context, scope store.Scope, ref workflow.Reference, output io.Writer) (*workflow.PortableExportReceipt, error) {
		return service.PreparePortablePartner(ctx, scope, ref.ID, event, output)
	}
}

func validatePortableOutput(path string) error {
	if path == "" {
		return errors.New("portable export requires a new output file in a private directory")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("portable export output must be a new file")
	}
	return nil
}

func portableConfigurationExport(ctx context.Context, dsn, token, tenant, partner, path, resource string, ref workflow.Reference, export configurationExporter, output io.Writer) error {
	if err := validatePortableOutput(path); err != nil {
		return err
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	service := workflow.Service{Custody: &custody.Service{DB: db}}
	return writePortableArtifact(ctx, path, resource, func(staged io.Writer) (*workflow.PortableExportReceipt, error) {
		return export(&service, ctx, scope, ref, staged)
	}, output)
}

func writePortableArtifact[Receipt any](ctx context.Context, path, resource string, prepare func(io.Writer) (*Receipt, error), output io.Writer) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	var receipt *Receipt
	stage, err := stageProtectedOutputAt(ctx, root, ".freightctl-"+resource+"-", resource+" export", func(staged io.Writer) error {
		var err error
		receipt, err = prepare(staged)
		return err
	})
	if err != nil {
		return err
	}
	if err = stage.publish(path); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(receipt)
}
