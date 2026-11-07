package main

import (
	"context"
	"encoding/json"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runProcessingProposal(ctx context.Context, command string, o processingReviewCLI) error {
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
	service := &workflow.Service{Custody: &custody.Service{DB: db}}
	decode := func(target any) error {
		secret, err := secure.ReadSecret(o.Input, 32<<10)
		if err != nil {
			return err
		}
		defer secret.Close()
		return workflow.Decode(secret.Bytes, target)
	}
	var value any
	switch command {
	case "processing-proposal-submit":
		var request workflow.ProcessingProposalRequest
		if err = decode(&request); err == nil {
			value, err = service.ProposeProcessingWorkflow(ctx, scope, o.Key, request)
		}
	case "processing-proposal-list":
		value, err = service.ProcessingProposals(ctx, scope, o.After, o.Limit)
	case "processing-proposal-status":
		value, err = service.ProcessingProposal(ctx, scope, o.ID)
	default:
		action, ok := map[string]string{"processing-proposal-adopt": "adopt", "processing-proposal-reject": "reject", "processing-proposal-withdraw": "withdraw"}[command]
		if !ok {
			return workflow.ErrInput
		}
		var decision workflow.Decision
		if err = decode(&decision); err == nil {
			value, err = service.DecideProcessingProposal(ctx, scope, o.ID, o.Key, action, decision)
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(value)
}
