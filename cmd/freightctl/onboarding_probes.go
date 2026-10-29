package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

type probeCLIOptions struct {
	DSN, Token, Tenant, Partner, Input, Key, Plan, ID, After, Hash string
	Limit                                                          int
}

func runOnboardingProbe(ctx context.Context, command string, o probeCLIOptions) error {
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
	var result any
	switch command {
	case "partner-onboarding-probe-list":
		result, err = service.ListOnboardingProbes(ctx, scope, o.Plan, o.After, o.Limit)
	case "partner-onboarding-probe-status":
		result, err = service.OnboardingProbeStatus(ctx, scope, o.ID)
	case "partner-onboarding-probe-work":
		result, err = service.WorkOnboardingProbe(ctx, scope, o.ID, o.Key, workflow.OnboardingProbeWorkRequest{Hash: o.Hash})
	case "partner-onboarding-probe-start":
		f, e := os.Open(o.Input)
		if e != nil {
			return errors.New("cannot open onboarding probe request reference")
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
		defer secure.Clear(data)
		var request store.OnboardingProbeRequest
		if workflow.Decode(data, &request) != nil {
			return workflow.ErrInput
		}
		result, err = service.StartOnboardingProbe(ctx, scope, o.Key, request)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
