package workflow

import (
	"context"
	"errors"
	"slices"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnboardingReleaseSelection struct {
	Plan      store.OnboardingReference `json:"plan"`
	TestIDs   []string                  `json:"test_ids"`
	Authority int64                     `json:"expected_authority_revision"`
}
type OnboardingReleaseProposal struct {
	Selection OnboardingReleaseSelection `json:"selection"`
	Hash      string                     `json:"definition_hash"`
}
type OnboardingReleasePreview struct {
	Definition       store.OnboardingReleaseDefinition `json:"definition"`
	Hash             string                            `json:"definition_hash"`
	Tests            []store.OnboardingTest            `json:"tests"`
	ExternalContact  bool                              `json:"external_contact"`
	ProductionActive bool                              `json:"production_active"`
}
type OnboardingReleaseResult struct {
	Kind    string                         `json:"kind"`
	Release store.OnboardingReleaseSummary `json:"release"`
}
type OnboardingReleaseView struct {
	Release          *store.OnboardingRelease `json:"release"`
	Tests            []store.OnboardingTest   `json:"tests"`
	Current          bool                     `json:"current_bindings"`
	Reason           string                   `json:"binding_reason"`
	ProductionActive bool                     `json:"production_active"`
}
type OnboardingProductionSelection struct {
	Decision
	RequirementID string `json:"requirement_id"`
	FileID        string `json:"file_id"`
}
type OnboardingProductionPreview struct {
	Definition      store.OnboardingDispatchDefinition `json:"definition"`
	Hash            string                             `json:"definition_hash"`
	ExternalContact bool                               `json:"external_contact"`
}
type OnboardingProductionStart struct {
	Definition store.OnboardingDispatchDefinition `json:"definition"`
}
type OnboardingProductionResult struct {
	Kind     string                    `json:"kind"`
	Dispatch *store.OnboardingDispatch `json:"dispatch"`
	Run      *store.WorkflowRun        `json:"run"`
}

func normalizeReleaseSelection(r OnboardingReleaseSelection) (OnboardingReleaseSelection, error) {
	if !validProbeReference(r.Plan) || r.Authority < 1 || len(r.TestIDs) < 1 || len(r.TestIDs) > 64 {
		return r, ErrInput
	}
	r.TestIDs = slices.Clone(r.TestIDs)
	slices.Sort(r.TestIDs)
	for i, id := range r.TestIDs {
		if !store.ValidID(id) || (i > 0 && id == r.TestIDs[i-1]) {
			return r, ErrInput
		}
	}
	return r, nil
}
func releaseSelection(d store.OnboardingReleaseDefinition) OnboardingReleaseSelection {
	r := OnboardingReleaseSelection{Plan: d.Plan, Authority: d.Authority}
	for _, p := range d.Proofs {
		r.TestIDs = append(r.TestIDs, p.TestID)
	}
	return r
}
func (s *Service) releasePreview(ctx context.Context, t *store.Transaction, r OnboardingReleaseSelection) (*OnboardingReleasePreview, error) {
	if r.Authority != t.AuthorityRevision || t.Root != "/" {
		return nil, store.ErrRevision
	}
	plan, err := t.OnboardingPlan(ctx, r.Plan.ID, 0)
	if err != nil {
		return nil, err
	}
	if plan.Version != r.Plan.Version || plan.Hash != r.Plan.Hash {
		return nil, store.ErrRevision
	}
	if len(r.TestIDs) != len(plan.Definition.Requirements) {
		return nil, ErrInput
	}
	tests := map[string]*store.OnboardingTest{}
	for _, id := range r.TestIDs {
		test, err := t.OnboardingTest(ctx, id)
		if err != nil {
			return nil, err
		}
		if test.Definition.Plan != r.Plan {
			return nil, store.ErrRevision
		}
		if tests[test.Definition.RequirementID] != nil {
			return nil, ErrInput
		}
		tests[test.Definition.RequirementID] = test
	}
	out := &OnboardingReleasePreview{Definition: store.OnboardingReleaseDefinition{Schema: 1, Profile: "sftp-outbound-production-v1", Plan: r.Plan, Authority: t.AuthorityRevision, Root: t.Root, Proofs: []store.OnboardingReleaseProof{}}, Tests: []store.OnboardingTest{}}
	for _, req := range plan.Definition.Requirements {
		if req.Direction != "send" || req.Protocol != "sftp" {
			return nil, ErrInput
		}
		test := tests[req.ID]
		if test == nil {
			return nil, ErrInput
		}
		current, _, err := s.testPreview(ctx, t, testPreviewRequest(test.Definition))
		if err != nil {
			return nil, err
		}
		if current.Hash != test.Hash {
			return nil, store.ErrRevision
		}
		d := test.Definition
		review, err := s.reviewExchange(ctx, t, OnboardingExchangeRequest{Plan: d.Plan, RequirementID: d.RequirementID, ProbeID: d.Probe.ID, RunID: test.RunID, StepID: d.StepID, ExpectedAuthority: d.Authority})
		if err != nil {
			return nil, err
		}
		if !review.Ready {
			return nil, store.ErrState
		}
		if out.Definition.StorageID == "" {
			out.Definition.StorageID = d.StorageID
		}
		if out.Definition.StorageID != d.StorageID {
			return nil, store.ErrRevision
		}
		out.Definition.Proofs = append(out.Definition.Proofs, store.OnboardingReleaseProof{RequirementID: req.ID, TestID: test.ID, TestHash: test.Hash, SnapshotHash: review.Hash, DeliveryID: review.Snapshot.Delivery.ID, DeliveryRevision: review.Snapshot.Delivery.Revision, ReceiptHash: review.Snapshot.ReceiptHash})
		out.Tests = append(out.Tests, *test)
	}
	_, out.Hash, err = digest(out.Definition)
	return out, err
}
func (s *Service) PreviewOnboardingRelease(ctx context.Context, scope store.Scope, input OnboardingReleaseSelection) (*OnboardingReleasePreview, error) {
	r, err := normalizeReleaseSelection(input)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	out, err := s.releasePreview(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return out, t.Tx.Commit(ctx)
}
func (s *Service) ProposeOnboardingRelease(ctx context.Context, scope store.Scope, key string, input OnboardingReleaseProposal) (*Result, error) {
	r, err := normalizeReleaseSelection(input.Selection)
	if err != nil || !hashPattern.MatchString(input.Hash) || !keyPattern.MatchString(key) {
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
		Kind      string
		Selection OnboardingReleaseSelection
		Hash      string
	}{"onboarding_release_propose", r, input.Hash})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	preview, err := s.releasePreview(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if preview.Hash != input.Hash {
		return nil, store.ErrRevision
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	release := &store.OnboardingRelease{OnboardingReleaseSummary: store.OnboardingReleaseSummary{ID: secure.NewID(), Plan: r.Plan, Author: t.Actor, Hash: preview.Hash, State: "proposed", Revision: 1, CreatedAt: now}, Definition: preview.Definition}
	if err = t.SaveOnboardingRelease(ctx, release, 0); err != nil {
		return nil, err
	}
	return releaseResult(ctx, t, key, meaning, release)
}
func releaseResult(ctx context.Context, t *store.Transaction, key, meaning string, r *store.OnboardingRelease) (*Result, error) {
	if err := t.WorkflowReceipt(ctx, key, meaning, r.ID, OnboardingReleaseResult{Kind: "onboarding_release", Release: r.OnboardingReleaseSummary}); err != nil {
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
func (s *Service) validateRelease(ctx context.Context, t *store.Transaction, r *store.OnboardingRelease) error {
	selection, err := normalizeReleaseSelection(releaseSelection(r.Definition))
	if err != nil {
		return store.ErrIsolation
	}
	current, err := s.releasePreview(ctx, t, selection)
	if err != nil {
		return err
	}
	if current.Hash != r.Hash {
		return store.ErrRevision
	}
	return nil
}
func (s *Service) DecideOnboardingRelease(ctx context.Context, scope store.Scope, id, action, key string, decision Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || decision.Revision < 1 || !hashPattern.MatchString(decision.Hash) || !slices.Contains([]string{"approve", "activate", "suspend", "revoke"}, action) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if action == "approve" || action == "revoke" {
		err = t.Require("workflow_approve")
	} else {
		err = t.Require("workflow_execute")
		if err == nil {
			err = t.Require("deliver")
		}
	}
	if err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"onboarding_release_decide", id, action, decision})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	r, err := t.OnboardingRelease(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Revision != decision.Revision || r.Hash != decision.Hash {
		return nil, store.ErrRevision
	}
	next := ""
	switch action {
	case "approve":
		if r.State == "proposed" {
			next = "approved"
		}
	case "activate":
		if r.State == "approved" || r.State == "suspended" {
			next = "active"
		}
	case "suspend":
		if r.State == "active" {
			next = "suspended"
		}
	case "revoke":
		if r.State != "revoked" {
			next = "revoked"
		}
	}
	if next == "" {
		return nil, store.ErrState
	}
	if next == "approved" || next == "active" {
		if err = s.validateRelease(ctx, t, r); err != nil {
			return nil, err
		}
	}
	if next == "active" {
		var occupied bool
		if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM onboarding_releases WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND plan_id=$4 AND state='active' AND release_id<>$5)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.Plan.ID, r.ID).Scan(&occupied); err != nil {
			return nil, err
		}
		if occupied {
			return nil, store.ErrConflict
		}
	}
	previous := r.Revision
	r.State = next
	r.Revision++
	if next == "approved" {
		r.ApprovedRevision = r.Revision
	}
	if err = t.SaveOnboardingRelease(ctx, r, previous); err != nil {
		return nil, err
	}
	return releaseResult(ctx, t, key, meaning, r)
}
func bindingChanged(err error) bool {
	return errors.Is(err, store.ErrState) || errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrForbidden) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrUnauthorized) || errors.Is(err, store.ErrLimit) || errors.Is(err, custody.ErrStorageIdentity)
}
func (s *Service) OnboardingReleaseStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingReleaseView, error) {
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
	r, err := t.OnboardingRelease(ctx, id, false)
	if err != nil {
		return nil, err
	}
	v := &OnboardingReleaseView{Release: r, Current: true, Reason: "current", Tests: []store.OnboardingTest{}}
	err = s.validateRelease(ctx, t, r)
	if err != nil {
		if !bindingChanged(err) {
			return nil, err
		}
		v.Current = false
		v.Reason = "binding_changed"
	}
	for _, p := range r.Definition.Proofs {
		test, err := t.OnboardingTest(ctx, p.TestID)
		if err != nil {
			return nil, err
		}
		v.Tests = append(v.Tests, *test)
	}
	v.ProductionActive = v.Current && r.State == "active"
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingReleases(ctx context.Context, scope store.Scope, plan, after string, limit int) (*store.OnboardingReleasePage, error) {
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
	page, err := t.OnboardingReleases(ctx, plan, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
func (s *Service) productionPreview(ctx context.Context, t *store.Transaction, id string, input OnboardingProductionSelection) (*OnboardingProductionPreview, *Definition, error) {
	r, err := t.OnboardingRelease(ctx, id, true)
	if err != nil {
		return nil, nil, err
	}
	if r.Hash != input.Hash || r.Revision != input.Revision {
		return nil, nil, store.ErrRevision
	}
	if r.State != "active" {
		return nil, nil, store.ErrState
	}
	if err = s.validateRelease(ctx, t, r); err != nil {
		return nil, nil, err
	}
	var testID string
	for _, p := range r.Definition.Proofs {
		if p.RequirementID == input.RequirementID {
			testID = p.TestID
			break
		}
	}
	if testID == "" {
		return nil, nil, ErrInput
	}
	test, err := t.OnboardingTest(ctx, testID)
	if err != nil {
		return nil, nil, err
	}
	d := test.Definition
	_, workflow, err := approved(ctx, t, Reference{ID: d.Workflow.ID, Version: d.Workflow.Version, Hash: d.Workflow.Hash})
	if err != nil {
		return nil, nil, err
	}
	if err = t.FileAccessible(ctx, input.FileID); err != nil {
		return nil, nil, err
	}
	file, err := t.File(ctx, input.FileID)
	if err != nil {
		return nil, nil, err
	}
	if file.Size > s.Custody.MaxFile {
		return nil, nil, store.ErrLimit
	}
	if err = s.checkStorage(d.StorageID); err != nil {
		return nil, nil, err
	}
	definition := store.OnboardingDispatchDefinition{Schema: 1, Release: store.OnboardingActivationReference{ID: id, Revision: r.Revision, Hash: r.Hash}, RequirementID: input.RequirementID, TestID: test.ID, TestHash: test.Hash, Workflow: d.Workflow, File: *file, StorageID: d.StorageID, Root: t.Root, Authority: t.AuthorityRevision, Effect: d.Effect}
	_, hash, err := digest(definition)
	return &OnboardingProductionPreview{Definition: definition, Hash: hash}, workflow, err
}
func validProductionSelection(r OnboardingProductionSelection) bool {
	return r.Revision > 0 && hashPattern.MatchString(r.Hash) && store.ValidID(r.RequirementID) && store.ValidID(r.FileID)
}
func (s *Service) PreviewOnboardingProduction(ctx context.Context, scope store.Scope, id string, r OnboardingProductionSelection) (*OnboardingProductionPreview, error) {
	if !store.ValidID(id) || !validProductionSelection(r) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	out, _, err := s.productionPreview(ctx, t, id, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return out, t.Tx.Commit(ctx)
}
func (s *Service) StartOnboardingProduction(ctx context.Context, scope store.Scope, key string, input OnboardingProductionStart) (*Result, error) {
	d := input.Definition
	r := OnboardingProductionSelection{Decision: Decision{Hash: d.Release.Hash, Revision: d.Release.Revision}, RequirementID: d.RequirementID, FileID: d.File.ID}
	if d.Schema != 1 || !keyPattern.MatchString(key) || !store.ValidID(d.Release.ID) || !validProductionSelection(r) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, true)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, err := digest(struct {
		Kind       string
		Definition store.OnboardingDispatchDefinition
	}{"onboarding_production_start", d})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	current, workflow, err := s.productionPreview(ctx, t, d.Release.ID, r)
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
	target, err := s.stageProduction(ctx, t, d, workflow)
	if err != nil {
		return nil, err
	}
	if err = t.WorkflowReceipt(ctx, key, meaning, target.Run.ID, target); err != nil {
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

// stageProduction commits nothing and makes no contact. Its caller owns the
// current-target validation, atomic domain transition and idempotency receipt.
func (s *Service) stageProduction(ctx context.Context, t *store.Transaction, d store.OnboardingDispatchDefinition, workflow *Definition) (*OnboardingProductionResult, error) {
	run, err := s.stageRun(ctx, t, RunRequest{Workflow: Reference{ID: d.Workflow.ID, Version: d.Workflow.Version, Hash: d.Workflow.Hash}, FileID: d.File.ID}, workflow, &d.File, d.StorageID)
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	dispatch := &store.OnboardingDispatch{ID: run.ID, Author: t.Actor, Definition: d, Hash: hash}
	if err = t.SaveOnboardingDispatch(ctx, dispatch); err != nil {
		return nil, err
	}
	return &OnboardingProductionResult{Kind: "onboarding_production", Dispatch: dispatch, Run: run}, nil
}

type OnboardingProductionView struct {
	Dispatch *store.OnboardingDispatch `json:"dispatch"`
	Status   *RunView                  `json:"status"`
	Current  bool                      `json:"current_bindings"`
}

func (s *Service) OnboardingProductionStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingProductionView, error) {
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
	d, err := t.OnboardingDispatch(ctx, id)
	if err != nil {
		return nil, err
	}
	run, err := t.WorkflowRun(ctx, id, false)
	if err != nil {
		return nil, err
	}
	view, _, _, err := snapshot(ctx, t, run)
	if err != nil {
		return nil, err
	}
	current, err := t.OnboardingRunCurrent(ctx, id)
	if err != nil {
		return nil, err
	}
	if current {
		if err = s.checkStorage(d.Definition.StorageID); err != nil {
			if !bindingChanged(err) {
				return nil, err
			}
			current = false
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &OnboardingProductionView{Dispatch: d, Status: view, Current: current}, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingProduction(ctx context.Context, scope store.Scope, release, after string, limit int) (*store.OnboardingDispatchPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.OnboardingRelease(ctx, release, false); err != nil {
		return nil, err
	}
	page, err := t.OnboardingDispatches(ctx, release, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
