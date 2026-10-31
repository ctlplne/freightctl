package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnboardingHandoffSelection struct {
	SourceRunID string                              `json:"source_run_id"`
	SourceHash  string                              `json:"source_hash"`
	Target      store.OnboardingActivationReference `json:"target_release"`
	FileID      string                              `json:"file_id"`
}
type OnboardingHandoffProposal struct {
	Definition store.OnboardingHandoffDefinition `json:"definition"`
}
type OnboardingHandoffPreview struct {
	Definition      store.OnboardingHandoffDefinition `json:"definition"`
	Hash            string                            `json:"definition_hash"`
	ExternalContact bool                              `json:"external_contact"`
}
type OnboardingHandoffResult struct {
	Kind    string                         `json:"kind"`
	Handoff store.OnboardingHandoffSummary `json:"handoff"`
}
type OnboardingHandoffView struct {
	Handoff         *store.OnboardingHandoff `json:"handoff"`
	Current         bool                     `json:"current_bindings"`
	Reason          string                   `json:"binding_reason"`
	ExternalContact bool                     `json:"external_contact"`
}

func validHandoffSelection(r OnboardingHandoffSelection) bool {
	return store.ValidID(r.SourceRunID) && hashPattern.MatchString(r.SourceHash) && store.ValidID(r.Target.ID) && r.Target.Revision > 0 && hashPattern.MatchString(r.Target.Hash) && store.ValidID(r.FileID)
}
func handoffSelection(d store.OnboardingHandoffDefinition) OnboardingHandoffSelection {
	return OnboardingHandoffSelection{SourceRunID: d.Source.Dispatch.ID, SourceHash: d.Source.Dispatch.Hash, Target: d.Target.Release, FileID: d.Target.File.ID}
}
func sameHandoffEffects(before, after store.OnboardingTestEffect) bool {
	if before.Address != after.Address || before.User != after.User || before.Directory != after.Directory || before.Filename != after.Filename || (before.Encryption == nil) != (after.Encryption == nil) {
		return false
	}
	return before.Encryption == nil || before.Encryption.Profile == after.Encryption.Profile
}

// handoffPreview holds the old run then intent row. Claim also locks the intent
// before incrementing attempts, so exactly one side can observe it untouched.
// Approval records the review but does not reserve either row after commit.
func (s *Service) handoffPreview(ctx context.Context, t *store.Transaction, r OnboardingHandoffSelection) (*OnboardingHandoffPreview, *store.WorkflowRun, *store.Delivery, *Definition, error) {
	original, err := t.OnboardingDispatch(ctx, r.SourceRunID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if original.Hash != r.SourceHash {
		return nil, nil, nil, nil, store.ErrRevision
	}
	run, err := t.WorkflowRun(ctx, r.SourceRunID, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if run.State == "cancelled" || run.State == "succeeded" {
		return nil, nil, nil, nil, store.ErrState
	}
	before := original.Definition
	if run.Source != before.File || run.StorageID != before.StorageID || run.Root != before.Root || run.Authority != before.Authority || run.WorkflowID != before.Workflow.ID || run.WorkflowVersion != before.Workflow.Version || run.WorkflowHash != before.Workflow.Hash {
		return nil, nil, nil, nil, store.ErrIsolation
	}
	steps, err := t.WorkflowSteps(ctx, run.ID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(steps) != 1 {
		return nil, nil, nil, nil, store.ErrIsolation
	}
	intent, err := t.Delivery(ctx, steps[0].DeliveryID, true)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if intent.State != "queued" || intent.Attempts != 0 || intent.Fence != 0 || intent.LeaseOwner != "" || intent.LeaseUntil != nil {
		return nil, nil, nil, nil, store.ErrState
	}
	if artifact, err := t.DeliveryCiphertext(ctx, intent.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, nil, nil, err
	} else if artifact != nil {
		return nil, nil, nil, nil, store.ErrState
	}
	prior, err := t.OnboardingRelease(ctx, before.Release.ID, false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	target, workflow, err := s.productionPreview(ctx, t, r.Target.ID, OnboardingProductionSelection{Decision: Decision{Revision: r.Target.Revision, Hash: r.Target.Hash}, RequirementID: before.RequirementID, FileID: r.FileID})
	if err != nil {
		return nil, nil, nil, nil, err
	}
	current, err := t.OnboardingRelease(ctx, r.Target.ID, false)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	after := target.Definition
	if prior.Plan != current.Plan || before.RequirementID != after.RequirementID || before.Workflow.ID != after.Workflow.ID || before.StorageID != after.StorageID || before.Root != after.Root || !sameHandoffEffects(before.Effect, after.Effect) || before.File.SHA256 != after.File.SHA256 || before.File.Size != after.File.Size {
		return nil, nil, nil, nil, store.ErrRevision
	}
	if before.Release == after.Release && before.File == after.File {
		return nil, nil, nil, nil, store.ErrState
	}
	if len(workflow.Steps) != 1 || workflow.Steps[0].ID != steps[0].ID {
		return nil, nil, nil, nil, store.ErrRevision
	}
	recheck, err := t.HandoffSourceRecheck(ctx, before.File.ID, after.File.ID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	definition := store.OnboardingHandoffDefinition{Schema: 1, Profile: "untouched-production-handoff-v1", Source: store.OnboardingHandoffSource{Dispatch: *original, Plan: prior.Plan, RunRevision: run.Revision, Delivery: store.OnboardingActivationReference{ID: intent.ID, Revision: intent.Revision, Hash: intent.DefinitionHash}, State: intent.State, Attempts: intent.Attempts, Fence: intent.Fence}, Target: after, TargetHash: target.Hash, SourceRecheckID: recheck}
	_, hash, err := digest(definition)
	return &OnboardingHandoffPreview{Definition: definition, Hash: hash}, run, intent, workflow, err
}
func (s *Service) PreviewOnboardingHandoff(ctx context.Context, scope store.Scope, r OnboardingHandoffSelection) (*OnboardingHandoffPreview, error) {
	if !validHandoffSelection(r) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	view, _, _, _, err := s.handoffPreview(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
func (s *Service) ProposeOnboardingHandoff(ctx context.Context, scope store.Scope, key string, input OnboardingHandoffProposal) (*Result, error) {
	d := input.Definition
	if !keyPattern.MatchString(key) || d.Schema != 1 || d.Profile != "untouched-production-handoff-v1" || !validHandoffSelection(handoffSelection(d)) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("workflow_manage"); err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind       string
		Definition store.OnboardingHandoffDefinition
	}{"onboarding_handoff_propose", d})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	current, _, _, _, err := s.handoffPreview(ctx, t, handoffSelection(d))
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	if hash != current.Hash {
		return nil, store.ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	h := &store.OnboardingHandoff{OnboardingHandoffSummary: store.OnboardingHandoffSummary{ID: secure.NewID(), Author: t.Actor, SourceRunID: d.Source.Dispatch.ID, Target: d.Target.Release, Hash: hash, State: "proposed", Revision: 1, CreatedAt: now}, Definition: d}
	if err = t.SaveOnboardingHandoff(ctx, h, 0); err != nil {
		return nil, err
	}
	return handoffResult(ctx, t, key, meaning, h)
}
func handoffResult(ctx context.Context, t *store.Transaction, key, meaning string, h *store.OnboardingHandoff) (*Result, error) {
	if err := t.WorkflowReceipt(ctx, key, meaning, h.ID, OnboardingHandoffResult{Kind: "onboarding_handoff", Handoff: h.OnboardingHandoffSummary}); err != nil {
		return nil, err
	}
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}
func (s *Service) DecideOnboardingHandoff(ctx context.Context, scope store.Scope, id, action, key string, decision Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || decision.Revision < 1 || !hashPattern.MatchString(decision.Hash) || (action != "approve" && action != "cancel" && action != "execute") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, action == "execute")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if action == "approve" {
		err = t.Require("workflow_approve")
	} else if action == "cancel" {
		err = t.Require("workflow_manage")
	}
	if err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"onboarding_handoff_decide", id, action, decision})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	h, err := t.OnboardingHandoff(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if h.Hash != decision.Hash || h.Revision != decision.Revision {
		return nil, store.ErrRevision
	}
	if (action == "approve" && h.State != "proposed") || (action == "execute" && h.State != "approved") || (action == "cancel" && h.State != "proposed" && h.State != "approved") {
		return nil, store.ErrState
	}
	previous := h.Revision
	if action == "cancel" {
		h.State = "cancelled"
	} else {
		current, run, intent, workflow, err := s.handoffPreview(ctx, t, handoffSelection(h.Definition))
		if err != nil {
			return nil, err
		}
		if current.Hash != h.Hash {
			return nil, store.ErrRevision
		}
		if action == "approve" {
			h.State = "approved"
		} else {
			// Zero attempts/lease/fence were checked while holding this exact row.
			// Cancel first within the transaction so replacement does not consume an
			// extra queue slot. Any later failure rolls back both sides and the receipt.
			prior := intent.Revision
			intent.State = "cancelled"
			intent.Revision++
			intent.Observation, _ = json.Marshal(map[string]string{"code": "onboarding_handoff", "handoff_id": h.ID})
			if err = t.SaveDelivery(ctx, intent, prior); err != nil {
				return nil, err
			}
			if err = setProjection(ctx, t, run, "cancelled", "onboarding_handoff"); err != nil {
				return nil, err
			}
			target, err := s.stageProduction(ctx, t, h.Definition.Target, workflow)
			if err != nil {
				return nil, err
			}
			h.State = "completed"
			h.NewRunID = target.Run.ID
		}
	}
	h.Revision++
	if err = t.SaveOnboardingHandoff(ctx, h, previous); err != nil {
		return nil, err
	}
	return handoffResult(ctx, t, key, meaning, h)
}
func (s *Service) OnboardingHandoffStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingHandoffView, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	h, err := t.OnboardingHandoff(ctx, id, false)
	if err != nil {
		return nil, err
	}
	v := &OnboardingHandoffView{Handoff: h, Reason: h.State}
	if h.State == "proposed" || h.State == "approved" {
		current, _, _, _, err := s.handoffPreview(ctx, t, handoffSelection(h.Definition))
		if err != nil {
			if !bindingChanged(err) {
				return nil, err
			}
			v.Reason = "binding_changed"
		} else if current.Hash != h.Hash {
			v.Reason = "binding_changed"
		} else {
			v.Current = true
			v.Reason = "current"
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingHandoffs(ctx context.Context, scope store.Scope, plan, after string, limit int) (*store.OnboardingHandoffPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.OnboardingPlan(ctx, plan, 0); err != nil {
		return nil, err
	}
	page, err := t.OnboardingHandoffs(ctx, plan, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
