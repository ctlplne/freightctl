package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type outputPolicyCLI struct {
	DSN, Token, Tenant, Partner, Input, Key, ID, After string
	Version, Limit                                     int
}

func runOutputPolicy(ctx context.Context, command string, o outputPolicyCLI) error {
	token, err := secure.ReadSecret(o.Token, 64)
	if err != nil {
		return err
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(token.Bytes)}
	token.Close()
	db, err := store.Open(ctx, o.DSN)
	if err != nil {
		return err
	}
	defer db.Pool.Close()
	s := &checks.Service{Custody: &custody.Service{DB: db}}
	decode := func(v any) error {
		b, e := secure.ReadSecret(o.Input, 32<<10)
		if e != nil {
			return e
		}
		defer b.Close()
		return workflow.Decode(b.Bytes, v)
	}
	var result any
	switch command {
	case "processing-output-policy-register":
		var r checks.OutputPolicyRequest
		if err = decode(&r); err == nil {
			result, err = s.RegisterOutputPolicy(ctx, scope, o.Key, r)
		}
	case "processing-output-policy-list":
		result, err = s.OutputPolicies(ctx, scope, o.After, o.Limit)
	case "processing-output-policy-status":
		result, err = s.OutputPolicy(ctx, scope, o.ID, o.Version)
	case "processing-output-policy-revoke":
		var d checks.PolicyDecision
		if err = decode(&d); err == nil {
			result, err = s.RevokeOutputPolicy(ctx, scope, o.ID, o.Version, o.Key, d)
		}
	default:
		return checks.ErrInput
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
