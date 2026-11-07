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

type processingReviewCLI struct {
	DSN, Token, Tenant, Partner, Input, Key, ID, After string
	Limit                                              int
}

func runProcessingReview(ctx context.Context, command string, options processingReviewCLI) error {
	secret, err := secure.ReadSecret(options.Token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: options.Tenant, Partner: options.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, err := store.Open(ctx, options.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	service := &workflow.Service{Custody: &custody.Service{DB: db}}
	decode := func(target any) error {
		b, e := secure.ReadSecret(options.Input, 32<<10)
		if e != nil {
			return e
		}
		defer b.Close()
		return workflow.Decode(b.Bytes, target)
	}
	var result any
	switch command {
	case "processing-review-request":
		var request workflow.ProcessingReviewRequest
		if err = decode(&request); err == nil {
			result, err = service.RequestProcessingReview(ctx, scope, options.Key, request)
		}
	case "processing-review-list":
		result, err = service.ProcessingReviews(ctx, scope, options.After, options.Limit)
	case "processing-review-status":
		result, err = service.ProcessingReview(ctx, scope, options.ID)
	default:
		actions := map[string]string{"processing-review-approve": "approve", "processing-review-reject": "reject", "processing-review-withdraw": "withdraw", "processing-review-adopt": "adopt"}
		action, ok := actions[command]
		if !ok {
			return workflow.ErrInput
		}
		var decision workflow.Decision
		if err = decode(&decision); err == nil {
			result, err = service.DecideProcessingReview(ctx, scope, options.ID, options.Key, action, decision)
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
