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

func runChecks(ctx context.Context, command, dsn, token, tenant, partner, storage, input, key, fileID, after string, limit, maxEntries int) error {
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
	custodyService := &custody.Service{DB: db, NamespaceMaxEntries: maxEntries}
	if command == "check-status" || command == "check-run" || command == "check-release" {
		disk, err := custody.OpenExisting(storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		custodyService.Disk = disk
	}
	service := &checks.Service{Custody: custodyService}
	decode := func(v any) error {
		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open check request reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return errors.New("check request must be bounded regular JSON")
		}
		data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return err
		}
		return workflow.Decode(data, v)
	}
	var result any
	switch command {
	case "check-list":
		result, err = service.List(ctx, scope, after, limit)
	case "intake-policy-register":
		var request checks.PolicyRequest
		if err = decode(&request); err != nil {
			return err
		}
		result, err = service.Register(ctx, scope, key, request)
	case "intake-policy-status":
		result, err = service.Policy(ctx, scope)
	case "intake-policy-revoke":
		var decision checks.PolicyDecision
		if err = decode(&decision); err != nil {
			return err
		}
		result, err = service.Revoke(ctx, scope, key, decision)
	case "check-status":
		result, err = service.Get(ctx, scope, fileID)
	case "check-run":
		result, err = service.Run(ctx, scope, fileID, key)
	case "check-release":
		var decision checks.ReleaseDecision
		if err = decode(&decision); err != nil {
			return err
		}
		result, err = service.Release(ctx, scope, fileID, key, decision)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
