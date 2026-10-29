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

func runRechecks(ctx context.Context, command, dsn, token, tenant, partner, storage, input, key, fileID, recheckID, after string, limit, maxEntries int, maxFile, maxStored int64) error {
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
	disk, err := custody.OpenExisting(storage)
	if err != nil {
		return err
	}
	defer disk.Close()
	service := &checks.Service{Custody: &custody.Service{DB: db, Disk: disk, MaxFile: maxFile, MaxStored: maxStored, NamespaceMaxEntries: maxEntries}}
	decode := func(v any) error {
		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open re-check request reference")
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
		return workflow.Decode(data, v)
	}
	var result any
	switch command {
	case "check-recheck-preview":
		var request checks.RecheckOptions
		if err = decode(&request); err == nil {
			result, err = service.PreviewRecheck(ctx, scope, fileID, request)
		}
	case "check-recheck-propose":
		var request struct {
			Plan checks.RecheckPlan `json:"plan"`
		}
		if err = decode(&request); err == nil {
			if request.Plan.Source.File.ID != fileID {
				return checks.ErrInput
			}
			result, err = service.ProposeRecheck(ctx, scope, key, request.Plan)
		}
	case "check-recheck-status":
		result, err = service.GetRecheck(ctx, scope, recheckID)
	case "check-recheck-list":
		result, err = service.ListRechecks(ctx, scope, fileID, after, limit)
	case "check-recheck-decide":
		var request checks.PolicyRecheckDecision
		if err = decode(&request); err == nil {
			result, err = service.DecideRecheck(ctx, scope, recheckID, key, request)
		}
	case "check-recheck-copy":
		result, err = service.CopyRecheck(ctx, scope, recheckID, key)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
