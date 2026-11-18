package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func portableWorkflowExport(ctx context.Context, dsn, token, tenant, partner, path string, ref workflow.Reference, output io.Writer) error {
	if path == "" {
		return errors.New("workflow export requires a new output file in a private directory")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("workflow export output must be a new file")
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
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	service := workflow.Service{Custody: &custody.Service{DB: db}}
	var receipt *workflow.PortableWorkflowReceipt
	stage, err := stageProtectedOutputAt(ctx, root, ".freightctl-workflow-", "workflow export", func(staged io.Writer) error {
		var err error
		receipt, err = service.PreparePortableWorkflow(ctx, scope, ref, staged)
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
