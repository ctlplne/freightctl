package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runScanner(ctx context.Context, command, dsn, token, tenant, partner, input, key, id, hash string, version int, revision int64) error {
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
	service := &checks.Service{Custody: &custody.Service{DB: db}}
	var result any
	switch command {
	case "scanner-register":
		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open scanner request reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return checks.ErrInput
		}
		data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return err
		}
		defer secure.Clear(data)
		var request checks.ScannerRequest
		if workflow.Decode(data, &request) != nil {
			return checks.ErrInput
		}
		result, err = service.RegisterScanner(ctx, scope, key, request)
		if err != nil {
			return err
		}
	case "scanner-status":
		result, err = service.Scanner(ctx, scope, id, version)
	case "scanner-revoke":
		result, err = service.RevokeScanner(ctx, scope, id, version, key, workflow.Decision{Hash: hash, Revision: revision})
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
