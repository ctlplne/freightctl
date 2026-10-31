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
	DSN, Token, Tenant, Partner, Storage, Input, Key, Plan, ID, After, Action, Run string
	Limit                                                                          int
	MaxFile, MaxStored                                                             int64
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
	case "partner-onboarding-observation-status":
		result, err = service.OnboardingObservationStatus(ctx, scope, o.ID)
	case "partner-onboarding-observation-list":
		result, err = service.ListOnboardingObservations(ctx, scope, o.Plan, o.After, o.Limit)

	case "partner-onboarding-handoff-status":
		result, err = service.OnboardingHandoffStatus(ctx, scope, o.ID)
	case "partner-onboarding-handoff-list":
		result, err = service.ListOnboardingHandoffs(ctx, scope, o.Plan, o.After, o.Limit)
	case "partner-onboarding-production-status":
		result, err = service.OnboardingProductionStatus(ctx, scope, o.Run)
	case "partner-onboarding-production-list":
		result, err = service.ListOnboardingProduction(ctx, scope, o.ID, o.After, o.Limit)
	case "partner-onboarding-release-list":
		result, err = service.ListOnboardingReleases(ctx, scope, o.Plan, o.After, o.Limit)
	case "partner-onboarding-release-status":
		result, err = service.OnboardingReleaseStatus(ctx, scope, o.ID)
	case "partner-onboarding-test-list":
		result, err = service.ListOnboardingTests(ctx, scope, o.Plan, o.After, o.Limit)
	case "partner-onboarding-test-status":
		result, err = service.OnboardingTestStatus(ctx, scope, o.ID)
	case "partner-onboarding-test-review":
		result, err = service.ReviewOnboardingTest(ctx, scope, o.ID)
	case "partner-onboarding-test-preview", "partner-onboarding-test-start", "partner-onboarding-release-preview", "partner-onboarding-release-propose", "partner-onboarding-release-decide", "partner-onboarding-production-preview", "partner-onboarding-production-start", "partner-onboarding-handoff-preview", "partner-onboarding-handoff-propose", "partner-onboarding-handoff-decide", "partner-onboarding-observation-preview", "partner-onboarding-observation-propose", "partner-onboarding-observation-decide", "partner-onboarding-observation-work":
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
		if command == "partner-onboarding-observation-preview" {
			var input workflow.OnboardingObservationSelection
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.PreviewOnboardingObservation(ctx, scope, input)
		} else if command == "partner-onboarding-observation-propose" {
			var input workflow.OnboardingObservationProposal
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.ProposeOnboardingObservation(ctx, scope, o.Key, input)
		} else if command == "partner-onboarding-observation-decide" {
			var input workflow.Decision
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.DecideOnboardingObservation(ctx, scope, o.ID, o.Action, o.Key, input)
		} else if command == "partner-onboarding-observation-work" {
			var input workflow.OnboardingProbeWorkRequest
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.WorkOnboardingObservation(ctx, scope, o.ID, o.Key, input)
		} else if command == "partner-onboarding-handoff-preview" {
			var input workflow.OnboardingHandoffSelection
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.PreviewOnboardingHandoff(ctx, scope, input)
		} else if command == "partner-onboarding-handoff-propose" {
			var input workflow.OnboardingHandoffProposal
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.ProposeOnboardingHandoff(ctx, scope, o.Key, input)
		} else if command == "partner-onboarding-handoff-decide" {
			var input workflow.Decision
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.DecideOnboardingHandoff(ctx, scope, o.ID, o.Action, o.Key, input)
		} else if command == "partner-onboarding-release-preview" {
			var input workflow.OnboardingReleaseSelection
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.PreviewOnboardingRelease(ctx, scope, input)
		} else if command == "partner-onboarding-release-propose" {
			var input workflow.OnboardingReleaseProposal
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.ProposeOnboardingRelease(ctx, scope, o.Key, input)
		} else if command == "partner-onboarding-release-decide" {
			var input workflow.Decision
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.DecideOnboardingRelease(ctx, scope, o.ID, o.Action, o.Key, input)
		} else if command == "partner-onboarding-production-preview" {
			var input workflow.OnboardingProductionSelection
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.PreviewOnboardingProduction(ctx, scope, o.ID, input)
		} else if command == "partner-onboarding-production-start" {
			var input workflow.OnboardingProductionStart
			if workflow.Decode(data, &input) != nil {
				return workflow.ErrInput
			}
			result, err = service.StartOnboardingProduction(ctx, scope, o.Key, input)
		} else if command == "partner-onboarding-test-preview" {
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
