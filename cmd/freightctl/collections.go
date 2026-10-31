package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runCollection(ctx context.Context, command string, o testCLIOptions) error {
	if o.MaxFile < 1 || o.MaxFile > 1<<30 || o.MaxStored < o.MaxFile {
		return errors.New("invalid collection storage budget")
	}
	token, e := secure.ReadSecret(o.Token, 64)
	if e != nil {
		return e
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(token.Bytes)}
	token.Close()
	db, e := store.Open(ctx, o.DSN)
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	c := &custody.Service{DB: db, MaxFile: o.MaxFile, MaxStored: o.MaxStored}
	switch command {
	case "workflow-collection-preview", "workflow-collection-start", "workflow-collection-work", "workflow-collection-refresh", "workflow-collection-routing-preview", "workflow-collection-routing-input-preview", "workflow-collection-routing-propose", "workflow-collection-routing-approve":
		disk, e := custody.OpenExisting(o.Storage)
		if e != nil {
			return e
		}
		defer disk.Close()
		c.Disk = disk
	}
	service := &workflow.Service{Custody: c}
	decode := func(target any) error {
		f, e := os.Open(o.Input)
		if e != nil {
			return errors.New("cannot open collection request reference")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return workflow.ErrInput
		}
		data, e := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if e != nil {
			return e
		}
		return workflow.Decode(data, target)
	}
	var out any
	switch command {
	case "workflow-collection-routing-preview", "workflow-collection-routing-input-preview":
		var x workflow.CollectionRoutingSelection
		if e = decode(&x); e == nil {
			if command == "workflow-collection-routing-input-preview" {
				out, e = service.PreviewCollectionRoutingInput(ctx, scope, o.ID, o.Plan, x)
			} else {
				out, e = service.PreviewCollectionRouting(ctx, scope, o.ID, x)
			}
		}
	case "workflow-collection-routing-propose":
		var x workflow.CollectionRoutingProposal
		if e = decode(&x); e == nil {
			out, e = service.ProposeCollectionRouting(ctx, scope, o.ID, o.Key, x)
		}
	case "workflow-collection-routing-status":
		out, e = service.CollectionRoutingStatus(ctx, scope, o.ID, o.Run)
	case "workflow-collection-routing-list":
		after := 0
		if o.After != "" {
			after, e = strconv.Atoi(o.After)
		}
		if e == nil {
			out, e = service.CollectionRoutingHistory(ctx, scope, o.ID, after, o.Limit)
		}
	case "workflow-collection-routing-approve", "workflow-collection-routing-revoke", "workflow-collection-routing-withdraw":
		var x workflow.Decision
		if e = decode(&x); e == nil {
			out, e = service.DecideCollectionRouting(ctx, scope, o.ID, o.Run, o.Key, strings.TrimPrefix(command, "workflow-collection-routing-"), x)
		}
	case "workflow-collection-preview":
		var x workflow.CollectionSelection
		if e = decode(&x); e == nil {
			out, e = service.PreviewCollection(ctx, scope, x)
		}
	case "workflow-collection-start":
		var x workflow.CollectionStartRequest
		if e = decode(&x); e == nil {
			out, e = service.StartCollection(ctx, scope, o.Key, x)
		}
	case "workflow-collection-work":
		var x workflow.CollectionWorkRequest
		if e = decode(&x); e == nil {
			out, e = service.WorkCollection(ctx, scope, o.ID, o.Key, x)
		}
	case "workflow-collection-status":
		out, e = service.CollectionStatus(ctx, scope, o.ID)
	case "workflow-collection-list":
		out, e = service.Collections(ctx, scope, o.After, o.Limit)
	case "workflow-collection-connections":
		out, e = service.CollectionConnections(ctx, scope, o.After, o.Limit)
	case "workflow-collection-workflows":
		out, e = service.CollectionWorkflows(ctx, scope, o.After, o.Limit)
	case "workflow-collection-refresh", "workflow-collection-cancel":
		var x workflow.Decision
		if e = decode(&x); e == nil {
			if command == "workflow-collection-cancel" {
				out, e = service.CancelCollection(ctx, scope, o.ID, o.Key, x)
			} else {
				out, e = service.RefreshCollection(ctx, scope, o.ID, o.Key, x)
			}
		}
	default:
		return workflow.ErrInput
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
