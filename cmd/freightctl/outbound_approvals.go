package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runOutboundApproval(ctx context.Context, command string, o testCLIOptions) error {
	secret, err := secure.ReadSecret(o.Token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, err := store.Open(ctx, o.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	custodyService := &custody.Service{DB: db, MaxFile: o.MaxFile, MaxStored: o.MaxStored}
	if command == "dispatch-review-preview" || command == "dispatch-review-propose" {
		disk, e := custody.OpenExisting(o.Storage)
		if e != nil {
			return e
		}
		defer disk.Close()
		custodyService.Disk = disk
	}
	s := &delivery.Service{Custody: custodyService}
	var result any
	switch command {
	case "dispatch-policy-status":
		result, err = s.DispatchPolicy(ctx, scope)
	case "dispatch-delivery-status":
		result, err = s.DispatchDelivery(ctx, scope, o.Run)
	case "dispatch-review-list":
		result, err = s.DispatchReviews(ctx, scope, o.After, o.Limit)
	case "dispatch-review-status":
		result, err = s.DispatchReview(ctx, scope, o.ID)
	default:
		f, e := os.Open(o.Input)
		if e != nil {
			return errors.New("cannot open dispatch approval request reference")
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 32<<10 {
			return errors.New("dispatch approval input must be bounded regular JSON")
		}
		data, e := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if e != nil || len(data) > 32<<10 {
			return delivery.ErrInput
		}
		switch command {
		case "dispatch-policy-set":
			var x delivery.DispatchPolicyChange
			if workflow.Decode(data, &x) != nil {
				return delivery.ErrInput
			}
			result, err = s.ChangeDispatchPolicy(ctx, scope, o.Key, x)
		case "dispatch-review-preview":
			var x delivery.DispatchSelection
			if workflow.Decode(data, &x) != nil {
				return delivery.ErrInput
			}
			result, err = s.PreviewDispatchReview(ctx, scope, x)
		case "dispatch-review-propose":
			var x delivery.DispatchProposal
			if workflow.Decode(data, &x) != nil {
				return delivery.ErrInput
			}
			result, err = s.ProposeDispatchReview(ctx, scope, o.Key, x)
		case "dispatch-review-decide":
			var x delivery.DispatchDecision
			if workflow.Decode(data, &x) != nil {
				return delivery.ErrInput
			}
			result, err = s.DecideDispatchReview(ctx, scope, o.ID, o.Action, o.Key, x)
		default:
			return delivery.ErrInput
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
