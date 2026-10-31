package workflow

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnboardingTestPreviewRequest struct {
	Plan              store.OnboardingReference `json:"plan"`
	RequirementID     string                    `json:"requirement_id"`
	ProbeID           string                    `json:"probe_id"`
	Workflow          Reference                 `json:"workflow"`
	FileID            string                    `json:"file_id"`
	ExpectedAuthority int64                     `json:"expected_authority_revision"`
}
type OnboardingTestStartRequest struct {
	Definition store.OnboardingTestDefinition `json:"definition"`
}
type OnboardingTestPreview struct {
	Definition       store.OnboardingTestDefinition `json:"definition"`
	Hash             string                         `json:"definition_hash"`
	Connection       *ConnectionView                `json:"connection"`
	Filename         string                         `json:"filename"`
	ExternalContact  bool                           `json:"external_contact"`
	ProductionActive bool                           `json:"production_active"`
}
type OnboardingTestResult struct {
	Kind string                `json:"kind"`
	Test *store.OnboardingTest `json:"test"`
	Run  *store.WorkflowRun    `json:"run"`
}
type OnboardingTestView struct {
	Test             *store.OnboardingTest `json:"test"`
	Status           *RunView              `json:"status"`
	Current          bool                  `json:"current_bindings"`
	Reason           string                `json:"binding_reason"`
	ProductionActive bool                  `json:"production_active"`
}

func validTestPreview(r OnboardingTestPreviewRequest) bool {
	return validProbeReference(r.Plan) && store.ValidID(r.RequirementID) && store.ValidID(r.ProbeID) && validProbeReference(store.OnboardingReference{ID: r.Workflow.ID, Version: r.Workflow.Version, Hash: r.Workflow.Hash}) && store.ValidID(r.FileID) && r.ExpectedAuthority > 0
}
func testPreviewRequest(d store.OnboardingTestDefinition) OnboardingTestPreviewRequest {
	return OnboardingTestPreviewRequest{Plan: d.Plan, RequirementID: d.RequirementID, ProbeID: d.Probe.ID, Workflow: Reference{ID: d.Workflow.ID, Version: d.Workflow.Version, Hash: d.Workflow.Hash}, FileID: d.File.ID, ExpectedAuthority: d.Authority}
}
func (s *Service) testBegin(ctx context.Context, scope store.Scope, execute bool) (*store.Transaction, error) {
	t, err := s.probeBegin(ctx, scope)
	if err != nil {
		return nil, err
	}
	if err = t.Require("read"); err != nil {
		t.Tx.Rollback(ctx)
		return nil, err
	}
	if execute {
		for _, grant := range []string{"workflow_execute", "deliver"} {
			if err = t.Require(grant); err != nil {
				t.Tx.Rollback(ctx)
				return nil, err
			}
		}
	} else if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}

	return t, nil
}
func (s *Service) testPreview(ctx context.Context, t *store.Transaction, r OnboardingTestPreviewRequest) (*OnboardingTestPreview, *Definition, error) {
	if t.AuthorityRevision != r.ExpectedAuthority || t.Root != "/" {
		return nil, nil, store.ErrRevision
	}
	p, err := t.OnboardingProbe(ctx, r.ProbeID, true)
	if err != nil {
		return nil, nil, err
	}
	if p.Definition.Plan != r.Plan || p.Definition.RequirementID != r.RequirementID {
		return nil, nil, store.ErrRevision
	}
	_, conn, err := probeBindings(ctx, t, p.Definition)
	if err != nil {
		return nil, nil, err
	}
	if p.State != "succeeded" || p.CompletedAt == nil || p.Observation.Code != "connectivity_verified" || !p.Observation.SSH || !p.Observation.SFTP || !p.Observation.Extensions || !p.Observation.Directory {
		return nil, nil, store.ErrState
	}
	plan, err := t.OnboardingPlan(ctx, r.Plan.ID, 0)
	if err != nil {
		return nil, nil, err
	}
	required := ""
	for _, req := range plan.Definition.Requirements {
		if req.ID == r.RequirementID {
			required = req.Receipt
			break
		}
	}
	wf, definition, err := approved(ctx, t, r.Workflow)
	if err != nil {
		return nil, nil, err
	}
	if len(definition.Steps) != 1 {
		return nil, nil, ErrInput
	}
	step := definition.Steps[0]
	connection := Reference{ID: p.Definition.Connection.ID, Version: p.Definition.Connection.Version, Hash: p.Definition.Connection.Hash}
	if step.Connection != connection {
		return nil, nil, store.ErrRevision
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, nil, err
	}
	file, err := t.File(ctx, r.FileID)
	if err != nil {
		return nil, nil, err
	}
	if file.Size > s.Custody.MaxFile {
		return nil, nil, store.ErrLimit
	}
	if s.Custody.Disk == nil {
		return nil, nil, store.ErrState
	}
	storage := s.Custody.Disk.Identity()
	if err = s.checkStorage(storage); err != nil {
		return nil, nil, err
	}
	effect := store.OnboardingTestEffect{Address: conn.Address, User: conn.User, Directory: conn.Directory, Filename: step.Filename, HostFingerprint: conn.HostFingerprint, KeyFingerprint: conn.KeyFingerprint, Encryption: step.Encryption}
	if step.Encryption != nil {
		key, err := t.EncryptionKey(ctx, *step.Encryption)
		if err != nil {
			return nil, nil, err
		}
		effect.RecipientFingerprint = key.Fingerprint
	}
	d := store.OnboardingTestDefinition{Schema: 1, Profile: "single-sftp-test-v1", Plan: r.Plan, RequirementID: r.RequirementID, Probe: store.OnboardingTestProbe{ID: p.ID, Revision: p.Revision, Hash: p.Hash}, Workflow: store.OnboardingReference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, WorkflowRevision: wf.Revision, StepID: step.ID, Connection: p.Definition.Connection, Effect: effect, File: *file, StorageID: storage, Root: t.Root, Authority: t.AuthorityRevision, RequiredReceipt: required}
	_, hash, err := digest(d)
	if err != nil {
		return nil, nil, err
	}
	return &OnboardingTestPreview{Definition: d, Hash: hash, Connection: conn, Filename: step.Filename}, definition, nil
}
func (s *Service) PreviewOnboardingTest(ctx context.Context, scope store.Scope, r OnboardingTestPreviewRequest) (*OnboardingTestPreview, error) {
	if !validTestPreview(r) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	view, _, err := s.testPreview(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
func (s *Service) StartOnboardingTest(ctx context.Context, scope store.Scope, key string, r OnboardingTestStartRequest) (*Result, error) {
	d := r.Definition
	if !keyPattern.MatchString(key) || !validTestPreview(testPreviewRequest(d)) || d.Schema != 1 || d.Profile != "single-sftp-test-v1" || d.Root != "/" || !hashPattern.MatchString(d.Probe.Hash) || d.Probe.Revision != 3 || !store.ValidID(d.StorageID) {
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
		Definition store.OnboardingTestDefinition
	}{"onboarding_test_start", d})
	if err != nil {
		return nil, err
	}
	// An exact historical receipt never queues another run. It remains private
	// to the currently authorized actor; current status/execution recheck bindings.
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	current, definition, err := s.testPreview(ctx, t, testPreviewRequest(d))
	if err != nil {
		return nil, err
	}
	_, requestedHash, err := digest(d)
	if err != nil {
		return nil, err
	}
	if requestedHash != current.Hash {
		return nil, store.ErrRevision
	}
	run, err := s.stageRun(ctx, t, RunRequest{Workflow: Reference{ID: d.Workflow.ID, Version: d.Workflow.Version, Hash: d.Workflow.Hash}, FileID: d.File.ID}, definition, &d.File, d.StorageID)
	if err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	p := &store.OnboardingTest{ID: run.ID, RunID: run.ID, Author: t.Actor, Definition: d, Hash: current.Hash, CreatedAt: now}
	if err = t.SaveOnboardingTest(ctx, p); err != nil {
		return nil, err
	}
	if err = t.WorkflowReceipt(ctx, key, meaning, p.ID, OnboardingTestResult{Kind: "onboarding_test", Test: p, Run: run}); err != nil {
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
func (s *Service) OnboardingTestStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingTestView, error) {
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
	p, err := t.OnboardingTest(ctx, id)
	if err != nil {
		return nil, err
	}
	run, err := t.WorkflowRun(ctx, p.RunID, false)
	if err != nil {
		return nil, err
	}
	view, _, _, err := snapshot(ctx, t, run)
	if err != nil {
		return nil, err
	}
	v := &OnboardingTestView{Test: p, Status: view, Reason: "current"}
	current, err := t.OnboardingRunCurrent(ctx, p.RunID)
	if err != nil {
		return nil, err
	}
	if current {
		_, _, bindingErr := approved(ctx, t, Reference{ID: p.Definition.Workflow.ID, Version: p.Definition.Workflow.Version, Hash: p.Definition.Workflow.Hash})
		if bindingErr == nil {
			bindingErr = t.FileAccessible(ctx, p.Definition.File.ID)
		}
		if bindingErr == nil {
			bindingErr = s.checkStorage(p.Definition.StorageID)
		}
		if bindingErr != nil {
			if !errors.Is(bindingErr, store.ErrState) && !errors.Is(bindingErr, store.ErrRevision) && !errors.Is(bindingErr, store.ErrNotFound) && !errors.Is(bindingErr, store.ErrForbidden) && !errors.Is(bindingErr, store.ErrUnauthorized) && !errors.Is(bindingErr, custody.ErrStorageIdentity) {
				return nil, bindingErr
			}
			current = false
		}
	}
	v.Current = current
	if !current {
		v.Reason = "binding_changed"
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingTests(ctx context.Context, scope store.Scope, plan, after string, limit int) (*store.OnboardingTestPage, error) {
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
	page, err := t.OnboardingTests(ctx, plan, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

// Evidence is selected through immutable pre-contact lineage, not supplied by
// the caller. The ordinary current review still evaluates receipt strength.
func (s *Service) ReviewOnboardingTest(ctx context.Context, scope store.Scope, id string) (*OnboardingExchangeReview, error) {
	v, err := s.OnboardingTestStatus(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	if !v.Current {
		return nil, store.ErrRevision
	}
	d := v.Test.Definition
	review, err := s.ReviewOnboardingExchange(ctx, scope, OnboardingExchangeRequest{Plan: d.Plan, RequirementID: d.RequirementID, ProbeID: d.Probe.ID, RunID: v.Test.RunID, StepID: d.StepID, ExpectedAuthority: d.Authority})
	if errors.Is(err, store.ErrNotFound) {
		return nil, store.ErrState
	}
	return review, err
}
