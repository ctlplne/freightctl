package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func runOnboarding(ctx context.Context, command, dsn, token, tenant, partner, input, key, id, after string, version, limit int) error {
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
	var result any
	switch command {
	case "partner-onboarding-status":
		result, err = db.Onboarding(ctx, scope, id, version)
	case "partner-onboarding-list":
		result, err = db.OnboardingPlans(ctx, scope, after, limit)
	case "partner-onboarding-save":
		f, e := os.Open(input)
		if e != nil {
			return errors.New("cannot open onboarding request reference")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return store.ErrOnboardingInput
		}
		data, e := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if e != nil {
			return e
		}
		defer secure.Clear(data)
		var request store.OnboardingCommand
		if workflow.Decode(data, &request) != nil {
			return store.ErrOnboardingInput
		}
		result, err = db.SaveOnboarding(ctx, scope, key, request)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
