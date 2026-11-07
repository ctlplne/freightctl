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

func runWorkflow(ctx context.Context, command, dsn, token, tenant, partner, storage, input, key, workflowID, connectionID, runID, hash string, version, againstVersion int, revision, maxFile, maxStored int64) error {
	if maxFile < 1 || maxFile > 1<<30 {
		return errors.New("invalid workflow file budget")
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
	custodyService := &custody.Service{DB: db, MaxFile: maxFile, MaxStored: maxStored}
	requiredStorage := command == "workflow-run" || command == "workflow-work" || command == "onward-preview" || command == "onward-start"
	inspectStorage := command == "workflow-run-status" || command == "workflow-refresh" || command == "workflow-cancel" || command == "workflow-validate" || command == "workflow-run-preview"
	if requiredStorage || (inspectStorage && storage != "") {
		disk, err := custody.OpenExisting(storage)
		if err != nil && requiredStorage {
			return err
		}
		if err == nil {
			defer disk.Close()
			custodyService.Disk = disk
		}
	}

	service := &workflow.Service{Custody: custodyService, Processor: &checks.Service{Custody: custodyService}}
	decode := func(v any) error {
		if command == "onward-preview" || command == "onward-start" || command == "onward-receipt" {
			request, err := secure.ReadSecret(input, 32<<10)
			if err != nil {
				return errors.New("onward request must be a protected bounded regular file")
			}
			defer request.Close()
			return workflow.Decode(request.Bytes, v)
		}

		f, err := os.Open(input)
		if err != nil {
			return errors.New("cannot open workflow request reference")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return errors.New("workflow request must be bounded regular JSON")
		}
		data, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return err
		}
		return workflow.Decode(data, v)
	}
	var result any
	decision := workflow.Decision{Hash: hash, Revision: revision}
	switch command {

	case "onward-receipt":
		var request workflow.OnwardLookup
		if err = decode(&request); err != nil {
			return err
		}
		result, err = service.OnwardReceipt(ctx, scope, request)
	case "onward-preview":
		var request workflow.OnwardRequest
		if err = decode(&request); err != nil {
			return err
		}
		result, err = service.PrepareOnward(ctx, scope, request)
	case "onward-start":
		var request workflow.OnwardStart
		if err = decode(&request); err != nil {
			return err
		}
		result, err = service.StartOnward(ctx, scope, key, request)
	case "connection-register":
		var r workflow.ConnectionRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.RegisterConnection(ctx, scope, key, r)
	case "connection-status":
		result, err = service.Connection(ctx, scope, connectionID, version)
	case "connection-revoke":
		result, err = service.RevokeConnection(ctx, scope, connectionID, version, key, decision)
	case "workflow-validate":
		var r workflow.PreviewRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.Validate(ctx, scope, r)
	case "workflow-draft":
		var r workflow.DraftRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.Draft(ctx, scope, key, r)
	case "workflow-status":
		result, err = service.Configuration(ctx, scope, workflowID, version)
	case "workflow-approve":
		result, err = service.Decide(ctx, scope, workflowID, version, key, "approve", decision)
	case "workflow-revoke":
		result, err = service.Decide(ctx, scope, workflowID, version, key, "revoke", decision)
	case "workflow-run":
		var r workflow.RunRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.Run(ctx, scope, key, r)
	case "workflow-run-preview":
		var r workflow.RunRequest
		if err = decode(&r); err != nil {
			return err
		}
		result, err = service.PreviewRun(ctx, scope, r)
	case "workflow-run-status":
		result, err = service.Status(ctx, scope, runID)
	case "workflow-refresh":
		result, err = service.RefreshRun(ctx, scope, runID, key)
	case "workflow-work":
		result, err = service.Work(ctx, scope, runID, key)
	case "workflow-diff":
		result, err = service.Diff(ctx, scope, workflowID, againstVersion, version)
	case "workflow-cancel":
		result, err = service.Cancel(ctx, scope, runID, key, decision)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
