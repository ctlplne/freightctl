package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

type OnboardingObservationSelection struct {
	SourceRunID string `json:"source_run_id"`
	SourceHash  string `json:"source_hash"`
	ProbeID     string `json:"probe_id"`
	FileID      string `json:"file_id"`
	Authority   int64  `json:"expected_authority_revision"`
}
type OnboardingObservationPreview struct {
	Definition       store.OnboardingObservationDefinition `json:"definition"`
	Hash             string                                `json:"definition_hash"`
	ExternalContact  bool                                  `json:"external_contact"`
	ResendAuthorized bool                                  `json:"resend_authorized"`
}
type OnboardingObservationProposal struct {
	Definition store.OnboardingObservationDefinition `json:"definition"`
}
type OnboardingObservationReceipt struct {
	Kind        string                             `json:"kind"`
	Observation store.OnboardingObservationSummary `json:"observation"`
}
type OnboardingObservationView struct {
	Observation      *store.OnboardingObservation `json:"observation"`
	Current          bool                         `json:"current_bindings"`
	Reason           string                       `json:"binding_reason"`
	ExternalContact  bool                         `json:"contact_attempted"`
	ResendAuthorized bool                         `json:"resend_authorized"`
	ObservedAt       time.Time                    `json:"observed_at"`
}

func validObservationSelection(r OnboardingObservationSelection) bool {
	return store.ValidID(r.SourceRunID) && hashPattern.MatchString(r.SourceHash) && store.ValidID(r.ProbeID) && store.ValidID(r.FileID) && r.Authority > 0
}
func observationSelection(d store.OnboardingObservationDefinition) OnboardingObservationSelection {
	return OnboardingObservationSelection{SourceRunID: d.Source.Dispatch.ID, SourceHash: d.Source.Dispatch.Hash, ProbeID: d.Probe.ID, FileID: d.File.ID, Authority: d.Authority}
}
func observationResult(code string) store.OnboardingObservationResult {
	return store.OnboardingObservationResult{Code: code, Business: "unknown", DirectoryDurability: "not established"}
}
func (s *Service) observationPreview(ctx context.Context, t *store.Transaction, r OnboardingObservationSelection) (*OnboardingObservationPreview, *ConnectionDefinition, error) {
	if t.Root != "/" || t.AuthorityRevision != r.Authority {
		return nil, nil, store.ErrRevision
	}
	dispatch, err := t.OnboardingDispatch(ctx, r.SourceRunID)
	if err != nil {
		return nil, nil, err
	}
	if dispatch.Hash != r.SourceHash {
		return nil, nil, store.ErrRevision
	}
	run, err := t.WorkflowRun(ctx, r.SourceRunID, true)
	if err != nil {
		return nil, nil, err
	}
	before := dispatch.Definition
	if run.State == "cancelled" || run.State == "succeeded" {
		return nil, nil, store.ErrState
	}
	if run.Source != before.File || run.StorageID != before.StorageID || run.Authority != before.Authority || run.Root != before.Root || run.WorkflowID != before.Workflow.ID || run.WorkflowVersion != before.Workflow.Version || run.WorkflowHash != before.Workflow.Hash {
		return nil, nil, store.ErrIsolation
	}
	steps, err := t.WorkflowSteps(ctx, run.ID)
	if err != nil {
		return nil, nil, err
	}
	if len(steps) != 1 {
		return nil, nil, store.ErrIsolation
	}
	step := steps[0]
	intent, err := t.Delivery(ctx, step.DeliveryID, true)
	if err != nil {
		return nil, nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, err
	}
	if intent.State != "ambiguous" && !(intent.State == "publishing" && intent.LeaseUntil != nil && !intent.LeaseUntil.After(now)) {
		return nil, nil, store.ErrState
	}
	var spec delivery.Definition
	if json.Unmarshal(intent.Definition, &spec) != nil {
		return nil, nil, store.ErrIsolation
	}
	_, hash, err := digest(spec)
	expected := store.ExecutionBinding{WorkflowID: run.WorkflowID, WorkflowVersion: run.WorkflowVersion, WorkflowHash: run.WorkflowHash, RunID: run.ID, StepID: step.ID, ConnectionID: step.ConnectionID, ConnectionVersion: step.ConnectionVersion, ConnectionHash: step.ConnectionHash}
	if err != nil || hash != intent.DefinitionHash || spec.Schema != 1 || spec.Binding == nil || *spec.Binding != expected || spec.Source != run.Source || intent.FileID != run.FileID || spec.StorageID != run.StorageID || spec.Root != run.Root || spec.Authority != run.Authority || spec.Destination.Address != before.Effect.Address || spec.Destination.User != before.Effect.User || spec.Destination.Host.Fingerprint != before.Effect.HostFingerprint || spec.Destination.KeyFingerprint != before.Effect.KeyFingerprint || spec.Directory != before.Effect.Directory || spec.Filename != before.Effect.Filename || !reflect.DeepEqual(spec.Encryption, before.Effect.Encryption) {
		return nil, nil, store.ErrIsolation
	}
	if !filenamePattern.MatchString(spec.Filename) {
		return nil, nil, store.ErrIsolation
	}
	prior, err := t.OnboardingRelease(ctx, before.Release.ID, false)
	if err != nil {
		return nil, nil, err
	}
	p, err := t.OnboardingProbe(ctx, r.ProbeID, true)
	if err != nil {
		return nil, nil, err
	}
	if p.Definition.Plan.ID != prior.Plan.ID || p.Definition.RequirementID != before.RequirementID || p.Definition.Connection.ID != step.ConnectionID {
		return nil, nil, store.ErrRevision
	}
	conn, view, err := probeBindings(ctx, t, p.Definition)
	if err != nil {
		return nil, nil, err
	}
	if p.State != "succeeded" || p.CompletedAt == nil || p.Observation.Code != "connectivity_verified" || !p.Observation.SSH || !p.Observation.SFTP || !p.Observation.Extensions || !p.Observation.Directory {
		return nil, nil, store.ErrState
	}
	if conn.Destination.Address != spec.Destination.Address || conn.Destination.User != spec.Destination.User || conn.Directory != spec.Directory {
		return nil, nil, store.ErrRevision
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, nil, err
	}
	file, err := t.File(ctx, r.FileID)
	if err != nil {
		return nil, nil, err
	}
	if file.SHA256 != spec.Source.SHA256 || file.Size != spec.Source.Size {
		return nil, nil, store.ErrRevision
	}
	if file.Size > s.Custody.MaxFile {
		return nil, nil, store.ErrLimit
	}
	recheck, err := t.HandoffSourceRecheck(ctx, spec.Source.ID, file.ID)
	if err != nil {
		return nil, nil, err
	}
	if err = s.checkStorage(spec.StorageID); err != nil {
		return nil, nil, err
	}
	wire := store.OnboardingObservationWire{SHA256: spec.Source.SHA256, Size: spec.Source.Size}
	cipher, err := t.DeliveryCiphertext(ctx, intent.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, nil, err
	}
	if spec.Encryption != nil {
		if cipher == nil || cipher.DeliveryID != intent.ID || cipher.SourceID != spec.Source.ID || cipher.SourceSHA256 != spec.Source.SHA256 || cipher.DefinitionHash != intent.DefinitionHash || cipher.StorageID != spec.StorageID || cipher.Policy != *spec.Encryption || cipher.Proof.Profile != spec.Encryption.Profile || cipher.Proof.PrimaryFingerprint != before.Effect.RecipientFingerprint || cipher.Proof.Cipher != "AES-256" || cipher.Size <= 0 || cipher.Size > secure.PGPCiphertextLimit(spec.Source.Size) || !hashPattern.MatchString(cipher.SHA256) {
			return nil, nil, store.ErrIsolation
		}
		wire.SHA256 = cipher.SHA256
		wire.Size = cipher.Size
		wire.Ciphertext = &store.OnboardingHandoffCiphertext{ObjectID: cipher.ObjectID, SHA256: cipher.SHA256, Size: cipher.Size}
	} else if cipher != nil {
		return nil, nil, store.ErrIsolation
	}
	plan, err := t.OnboardingPlan(ctx, prior.Plan.ID, prior.Plan.Version)
	if err != nil {
		return nil, nil, err
	}
	required := ""
	for _, req := range plan.Definition.Requirements {
		if req.ID == before.RequirementID {
			required = req.Receipt
		}
	}
	if required != "transport" && required != "integrity" && required != "business" {
		return nil, nil, store.ErrIsolation
	}
	d := store.OnboardingObservationDefinition{Schema: 1, Profile: "sftp-published-observation-v1", Source: store.OnboardingHandoffSource{Dispatch: *dispatch, Plan: prior.Plan, RunRevision: run.Revision, Delivery: store.OnboardingActivationReference{ID: intent.ID, Revision: intent.Revision, Hash: intent.DefinitionHash}, State: intent.State, Attempts: intent.Attempts, Fence: intent.Fence}, OriginalConnection: store.OnboardingReference{ID: step.ConnectionID, Version: step.ConnectionVersion, Hash: step.ConnectionHash}, File: *file, SourceRecheckID: recheck, Probe: store.OnboardingActivationReference{ID: p.ID, Revision: p.Revision, Hash: p.Hash}, Observer: p.Definition, Effect: store.OnboardingObservationEffect{Address: view.Address, User: view.User, Directory: view.Directory, Path: path.Join(view.Directory, intent.ID+"-"+spec.Filename), HostFingerprint: view.HostFingerprint, KeyFingerprint: view.KeyFingerprint}, Wire: wire, RequiredReceipt: required, StorageID: spec.StorageID, Root: t.Root, Authority: t.AuthorityRevision}
	_, hash, err = digest(d)
	return &OnboardingObservationPreview{Definition: d, Hash: hash}, conn, err
}
func (s *Service) PreviewOnboardingObservation(ctx context.Context, scope store.Scope, r OnboardingObservationSelection) (*OnboardingObservationPreview, error) {
	if !validObservationSelection(r) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	v, _, err := s.observationPreview(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func observationReceipt(ctx context.Context, t *store.Transaction, key, meaning string, o *store.OnboardingObservation) (*Result, error) {
	if err := t.WorkflowReceipt(ctx, key, meaning, o.ID, OnboardingObservationReceipt{Kind: "onboarding_observation", Observation: o.OnboardingObservationSummary}); err != nil {
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
func (s *Service) ProposeOnboardingObservation(ctx context.Context, scope store.Scope, key string, r OnboardingObservationProposal) (*Result, error) {
	d := r.Definition
	if !keyPattern.MatchString(key) || d.Schema != 1 || d.Profile != "sftp-published-observation-v1" || !validObservationSelection(observationSelection(d)) {
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
		Definition store.OnboardingObservationDefinition
	}{"onboarding_observation_propose", d})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	current, _, err := s.observationPreview(ctx, t, observationSelection(d))
	if err != nil {
		return nil, err
	}
	_, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	if current.Hash != hash {
		return nil, store.ErrRevision
	}
	if err = t.OnboardingObservationAdmission(ctx); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	o := &store.OnboardingObservation{OnboardingObservationSummary: store.OnboardingObservationSummary{ID: secure.NewID(), Author: t.Actor, SourceRunID: d.Source.Dispatch.ID, Hash: hash, State: "proposed", Revision: 1, Result: observationResult("awaiting_review"), CreatedAt: now}, Definition: d}
	if err = t.SaveOnboardingObservation(ctx, o, 0); err != nil {
		return nil, err
	}
	return observationReceipt(ctx, t, key, meaning, o)
}
func (s *Service) DecideOnboardingObservation(ctx context.Context, scope store.Scope, id, action, key string, r Decision) (*Result, error) {
	if !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(r.Hash) || r.Revision < 1 || (action != "approve" && action != "cancel") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.testBegin(ctx, scope, false)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	grant := "workflow_manage"
	if action == "approve" {
		grant = "workflow_approve"
	}
	if err = t.Require(grant); err != nil {
		return nil, err
	}
	_, meaning, err := digest(struct {
		Kind, ID, Action string
		Decision         Decision
	}{"onboarding_observation_decide", id, action, r})
	if err != nil {
		return nil, err
	}
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	o, err := t.OnboardingObservation(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if o.Hash != r.Hash || o.Revision != r.Revision {
		return nil, store.ErrRevision
	}
	if (action == "approve" && o.State != "proposed") || (action == "cancel" && o.State != "proposed" && o.State != "approved") {
		return nil, store.ErrState
	}
	previous := o.Revision
	if action == "approve" {
		current, _, err := s.observationPreview(ctx, t, observationSelection(o.Definition))
		if err != nil {
			return nil, err
		}
		if current.Hash != o.Hash {
			return nil, store.ErrRevision
		}
		o.State = "approved"
		o.Result = observationResult("approved")
	} else {
		o.State = "cancelled"
		o.Result = observationResult("cancelled")
		now, err := t.DatabaseTime(ctx)
		if err != nil {
			return nil, err
		}
		o.CompletedAt = &now
	}
	o.Revision++
	if err = t.SaveOnboardingObservation(ctx, o, previous); err != nil {
		return nil, err
	}
	return observationReceipt(ctx, t, key, meaning, o)
}
func (s *Service) observationView(ctx context.Context, t *store.Transaction, o *store.OnboardingObservation) (*OnboardingObservationView, error) {
	v := &OnboardingObservationView{Observation: o, Reason: o.State}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	v.ObservedAt = now
	if o.State == "proposed" || o.State == "approved" || o.State == "running" {
		current, _, err := s.observationPreview(ctx, t, observationSelection(o.Definition))
		if err != nil {
			if !bindingChanged(err) {
				return nil, err
			}
			v.Reason = "binding_changed"
		} else if current.Hash != o.Hash {
			v.Reason = "binding_changed"
		} else {
			v.Current = true
			v.Reason = "current"
		}
	}
	return v, nil
}
func (s *Service) OnboardingObservationStatus(ctx context.Context, scope store.Scope, id string) (*OnboardingObservationView, error) {
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
	o, err := t.OnboardingObservation(ctx, id, false)
	if err != nil {
		return nil, err
	}
	v, err := s.observationView(ctx, t, o)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
func (s *Service) ListOnboardingObservations(ctx context.Context, scope store.Scope, plan, after string, limit int) (*store.OnboardingObservationPage, error) {
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
	v, err := t.OnboardingObservations(ctx, plan, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return v, t.Tx.Commit(ctx)
}
