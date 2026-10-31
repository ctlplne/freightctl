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

type testCLIOptions struct {
	DSN, Token, Tenant, Partner, Storage, Input, Key, Plan, ID, After string
	Limit                                                             int
	MaxFile, MaxStored                                                int64
}

func runOnboardingTest(ctx context.Context, command string, o testCLIOptions) error {
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
	disk, err := custody.OpenExisting(o.Storage)
	if err != nil {
		return err
	}
	defer disk.Close()
	service := &workflow.Service{Custody: &custody.Service{DB: db, Disk: disk, MaxFile: o.MaxFile, MaxStored: o.MaxStored}}
	var result any
	switch command {
	case "partner-onboarding-test-list":
		result, err = service.ListOnboardingTests(ctx, scope, o.Plan, o.After, o.Limit)
	case "partner-onboarding-test-status":
		result, err = service.OnboardingTestStatus(ctx, scope, o.ID)
	case "partner-onboarding-test-review":
		result, err = service.ReviewOnboardingTest(ctx, scope, o.ID)
	case "partner-onboarding-test-preview", "partner-onboarding-test-start":
		f, e := os.Open(o.Input)
		if e != nil {
			return errors.New("cannot open onboarding test request reference")
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
		if command == "partner-onboarding-test-preview" {
			var input workflow.OnboardingTestPreviewRequest
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.PreviewOnboardingTest(ctx, scope, input)
		} else {
			var input workflow.OnboardingTestStartRequest
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.StartOnboardingTest(ctx, scope, o.Key, input)
		}
	default:
		return workflow.ErrInput
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
