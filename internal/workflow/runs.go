package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func approved(ctx context.Context, t *store.Transaction, ref Reference) (*store.Configuration, *Definition, error) {
	if !store.ValidID(ref.ID) || ref.Version < 1 || !hashPattern.MatchString(ref.Hash) {
		return nil, nil, ErrInput
	}
	c, err := t.Configuration(ctx, false, ref.ID, ref.Version, false)
	if err != nil {
		return nil, nil, err
	}
	if c.Hash != ref.Hash {
		return nil, nil, store.ErrRevision
	}
	if c.State != "approved" || c.ApprovalAuthority != t.AuthorityRevision {
		return nil, nil, store.ErrState
	}
	var d Definition
	if err = Decode(c.Definition, &d); err != nil {
		return nil, nil, err
	}
	d, err = Normalize(d)
	if err != nil {
		return nil, nil, err
	}
	_, hash, err := digest(d)
	if err != nil || hash != c.Hash {
		return nil, nil, store.ErrState
	}
	if _, err = connections(ctx, t, d); err != nil {
		return nil, nil, err
	}
	return c, &d, nil
}
func (s *Service) checkStorage(id string) error {
	if s.Custody.Disk == nil || s.Custody.Disk.Identity() != id {
		return custody.ErrStorageIdentity
	}
	return s.Custody.Disk.CheckIdentity()
}
func (s *Service) Run(ctx context.Context, scope store.Scope, key string, r RunRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(r.FileID) {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, definition, err := approved(ctx, t, r.Workflow)
	if err != nil {
		return nil, err
	}
	if definition.Source != nil {
		return nil, ErrInput
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, err
	}
	source, err := t.File(ctx, r.FileID)
	if err != nil {
		return nil, err
	}
	if source.Size > s.Custody.MaxFile {
		return nil, store.ErrLimit
	}
	if s.Custody.Disk == nil {
		return nil, custody.ErrStorageIdentity
	}
	storageID := s.Custody.Disk.Identity()
	if err = s.checkStorage(storageID); err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind      string
		Request   RunRequest
		Authority int64
		Storage   string
	}{"create_run", r, t.AuthorityRevision, storageID})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	run, err := s.stageRun(ctx, t, r, definition, source, storageID)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, run.ID, run)
}

// stageRun writes the ordinary run and delivery intents in its caller's
// transaction. It makes no network contact and never commits that transaction.
func (s *Service) stageRun(ctx context.Context, t *store.Transaction, r RunRequest, definition *Definition, source *store.File, storageID string) (*store.WorkflowRun, error) {
	if err := t.DeliveryAdmission(ctx, len(definition.Steps)); err != nil {
		return nil, err
	}
	run := &store.WorkflowRun{ID: secure.NewID(), WorkflowID: r.Workflow.ID, WorkflowVersion: r.Workflow.Version, WorkflowHash: r.Workflow.Hash, FileID: source.ID, Source: *source, StorageID: storageID, Root: t.Root, Authority: t.AuthorityRevision, State: "queued", Reason: "awaiting_worker", Revision: 1}
	if err := t.SaveWorkflowRun(ctx, run, 0); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	for index, step := range definition.Steps {
		c, err := t.Configuration(ctx, true, step.Connection.ID, step.Connection.Version, false)
		if err != nil {
			return nil, err
		}
		var conn ConnectionDefinition
		if err = json.Unmarshal(c.Definition, &conn); err != nil {
			return nil, store.ErrState
		}
		binding := &store.ExecutionBinding{WorkflowID: run.WorkflowID, WorkflowVersion: run.WorkflowVersion, WorkflowHash: run.WorkflowHash, RunID: run.ID, StepID: step.ID, ConnectionID: c.ID, ConnectionVersion: c.Version, ConnectionHash: c.Hash}
		spec := delivery.Definition{Schema: 1, Source: *source, Destination: conn.Destination, Directory: conn.Directory, Filename: step.Filename, StorageID: storageID, Root: t.Root, Authority: t.AuthorityRevision, Binding: binding, Encryption: step.Encryption}
		if err = delivery.BindDispatchPolicy(ctx, t, &spec); err != nil {
			return nil, err
		}
		data, hash, err := digest(spec)
		if err != nil {
			return nil, err
		}
		intent := &store.Delivery{ID: secure.NewID(), FileID: source.ID, Definition: data, DefinitionHash: hash, State: "draft", Revision: 1, NextAt: now, Observation: json.RawMessage(`{}`)}
		if err = t.SaveDelivery(ctx, intent, 0); err != nil {
			return nil, err
		}
		intent.State = "queued"
		intent.Revision++
		if err = t.SaveDelivery(ctx, intent, 1); err != nil {
			return nil, err
		}
		if err = t.BindWorkflowStep(ctx, &store.WorkflowStep{RunID: run.ID, ID: step.ID, Ordinal: index + 1, ConnectionID: c.ID, ConnectionVersion: c.Version, ConnectionHash: c.Hash, DeliveryID: intent.ID}); err != nil {
			return nil, err
		}
	}
	return run, nil
}
func snapshot(ctx context.Context, t *store.Transaction, r *store.WorkflowRun) (*RunView, string, string, error) {
	steps, err := t.WorkflowSteps(ctx, r.ID)
	if err != nil {
		return nil, "", "", err
	}
	if len(steps) < 1 {
		return nil, "", "", store.ErrState
	}
	view := &RunView{Run: r, Steps: []RunStepView{}}
	succeeded := 0
	reason := "awaiting_worker"
	state := "queued"
	if r.State == "running" {
		state = "running"
		reason = r.Reason
	}
	for _, step := range steps {
		d, err := t.Delivery(ctx, step.DeliveryID, false)
		if err != nil {
			return nil, "", "", err
		}
		item := RunStepView{ID: step.ID, Ordinal: step.Ordinal, DeliveryID: d.ID, State: d.State, Attempts: d.Attempts, Observation: d.Observation}
		item.Ciphertext, err = t.DeliveryCiphertext(ctx, d.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, "", "", err
		}
		view.Steps = append(view.Steps, item)
		switch d.State {
		case "succeeded":
			succeeded++
			if state != "attention" {
				state = "running"
				reason = "awaiting_worker"
			}
		case "ambiguous":
			state = "attention"
			reason = "delivery_ambiguous"
		case "blocked", "cancelled":
			if reason != "delivery_ambiguous" {
				state = "attention"
				reason = "delivery_blocked"
			}
		case "staging", "publishing", "retry":
			if state != "attention" {
				state = "running"
				reason = "delivery_in_progress"
			}
		}
	}
	if succeeded == len(steps) {
		state = "succeeded"
		reason = "all_integrity_receipts_observed"
	}
	if r.State == "cancelled" {
		state = "cancelled"
		reason = "operator_cancelled"
	}
	// Configuration revocation remains visible if a worker stopped before it could
	// update the projection. Observation alone is never a delivery receipt.
	if state != "succeeded" && state != "cancelled" {
		wf, err := t.Configuration(ctx, false, r.WorkflowID, r.WorkflowVersion, false)
		if err != nil {
			return nil, "", "", err
		}
		if wf.State != "approved" {
			state = "attention"
			reason = "workflow_not_approved"
		}
		for _, step := range steps {
			c, err := t.Configuration(ctx, true, step.ConnectionID, step.ConnectionVersion, false)
			if err != nil {
				return nil, "", "", err
			}
			if c.State != "active" {
				state = "attention"
				reason = "connection_revoked"
			}
		}
		var definition Definition
		if json.Unmarshal(wf.Definition, &definition) != nil {
			return nil, "", "", store.ErrState
		}
		for _, step := range definition.Steps {
			if step.Encryption != nil {
				if _, err = t.EncryptionKey(ctx, *step.Encryption); err != nil {
					if err != store.ErrState && err != store.ErrNotFound {
						return nil, "", "", err
					}
					state = "attention"
					reason = "encryption_recipient_unavailable"
				}
			}
		}
	}
	if state != "succeeded" && state != "cancelled" {
		current, err := t.OnboardingRunCurrent(ctx, r.ID)
		if err != nil {
			return nil, "", "", err
		}
		if !current {
			state = "attention"
			reason = "onboarding_binding_changed"
		}
	}
	if state != "succeeded" && state != "cancelled" {
		if e := t.ScheduleBindingStatus(ctx, r.ID); e != nil {
			if !errors.Is(e, store.ErrSchedule) {
				return nil, "", "", e
			}
			state = "attention"
			reason = "schedule_authority_or_deadline_changed"
		}
	}
	if state != "succeeded" && state != "cancelled" {
		if e := t.CollectionBindingStatus(ctx, r.ID); e != nil {
			if !errors.Is(e, store.ErrCollection) {
				return nil, "", "", e
			}
			state = "attention"
			reason = "collection_authority_or_deadline_changed"
		}
	}
	view.ObservedState = state
	view.ObservedReason = reason
	return view, state, reason, nil
}
func (s *Service) Status(ctx context.Context, scope store.Scope, id string) (*RunView, error) {
	t, err := s.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	r, err := t.WorkflowRun(ctx, id, false)
	if err != nil {
		return nil, err
	}
	if err = t.Require("read"); err != nil {
		return nil, err
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, err
	}
	view, _, _, err := snapshot(ctx, t, r)
	if err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
func setProjection(ctx context.Context, t *store.Transaction, r *store.WorkflowRun, state, reason string) error {
	if r.State == state && r.Reason == reason {
		return nil
	}
	if r.State == "succeeded" || r.State == "cancelled" {
		return nil
	}
	previous := r.Revision
	r.State = state
	r.Reason = reason
	r.Revision++
	return t.SaveWorkflowRun(ctx, r, previous)
}

type Dispatch struct {
	RunID      string `json:"run_id"`
	DeliveryID string `json:"delivery_id"`
	StepID     string `json:"step_id"`
}
type WorkResult struct {
	Dispatch Dispatch `json:"dispatch"`
	Replayed bool     `json:"replayed"`
	Status   *RunView `json:"status"`
}

func (s *Service) prepare(ctx context.Context, scope store.Scope, id, key string) (*Dispatch, bool, error) {
	if !keyPattern.MatchString(key) {
		return nil, false, ErrInput
	}
	t, err := s.begin(ctx, scope, "workflow_execute", "read", "deliver")
	if err != nil {
		return nil, false, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct{ Kind, ID string }{"dispatch_run_step", id})
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, false, err
	}
	r, err := t.WorkflowRun(ctx, id, true)
	if err != nil {
		return nil, false, err
	}
	if r.Authority != t.AuthorityRevision || r.Root != t.Root {
		return nil, false, store.ErrUnauthorized
	}
	if err = s.checkStorage(r.StorageID); err != nil {
		return nil, false, err
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, false, err
	}
	if _, _, err = approved(ctx, t, Reference{ID: r.WorkflowID, Version: r.WorkflowVersion, Hash: r.WorkflowHash}); err != nil {
		return nil, false, err
	}
	current, err := t.OnboardingRunCurrent(ctx, r.ID)
	if err != nil {
		return nil, false, err
	}
	if !current {
		return nil, false, store.ErrState
	}
	if data != nil {
		var dispatch Dispatch
		if err = json.Unmarshal(data, &dispatch); err != nil {
			return nil, false, err
		}
		if dispatch.RunID != id {
			return nil, false, store.ErrConflict
		}
		return &dispatch, true, t.Tx.Commit(ctx)
	}
	if r.State == "succeeded" || r.State == "cancelled" {
		return nil, false, store.ErrState
	}
	view, state, reason, err := snapshot(ctx, t, r)
	if err != nil {
		return nil, false, err
	}
	if state == "succeeded" || reason == "connection_revoked" || reason == "workflow_not_approved" {
		return nil, false, store.ErrState
	}
	var dispatch *Dispatch
	for _, step := range view.Steps {
		if step.State == "succeeded" {
			continue
		}
		if step.State == "blocked" || step.State == "ambiguous" || step.State == "cancelled" {
			return nil, false, store.ErrState
		}
		dispatch = &Dispatch{RunID: id, DeliveryID: step.DeliveryID, StepID: step.ID}
		break
	}
	if dispatch == nil {
		return nil, false, store.ErrState
	}
	if err = setProjection(ctx, t, r, "running", "dispatch_prepared"); err != nil {
		return nil, false, err
	}
	if err = t.WorkflowReceipt(ctx, key, meaning, id, dispatch); err != nil {
		return nil, false, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, false, err
	}
	return dispatch, false, t.Tx.Commit(ctx)
}
func (s *Service) refresh(ctx context.Context, scope store.Scope, id string) (*RunView, error) {
	t, err := s.begin(ctx, scope, "workflow_execute", "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	r, err := t.WorkflowRun(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Authority != t.AuthorityRevision || r.Root != t.Root {
		return nil, store.ErrUnauthorized
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, err
	}
	view, state, reason, err := snapshot(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if err = setProjection(ctx, t, r, state, reason); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}

// Work's stable request key fixes one selected intent before any external call.
// Replaying that key cannot accidentally advance to the next workflow step.
func (s *Service) Work(ctx context.Context, scope store.Scope, id, key string) (*WorkResult, error) {
	dispatch, replayed, err := s.prepare(ctx, scope, id, key)
	if err != nil {
		return nil, err
	}
	sender := &delivery.Service{Custody: s.Custody}
	d, err := sender.Status(ctx, scope, dispatch.DeliveryID)
	if err != nil {
		return nil, err
	}
	if d.State != "succeeded" {
		if _, err = sender.Work(ctx, scope, dispatch.DeliveryID); err != nil {
			return nil, err
		}
	}
	view, err := s.refresh(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	return &WorkResult{Dispatch: *dispatch, Replayed: replayed, Status: view}, nil
}

// RefreshRun records the current projection from ordinary immutable receipts.
// It performs no transfer and can close a worker-crash gap after every intent
// succeeded, including when a scheduled sending window has since closed.
func (s *Service) RefreshRun(ctx context.Context, scope store.Scope, id, key string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !store.ValidID(id) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	t, e := s.begin(ctx, scope, "workflow_execute", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, e := digest(struct{ Kind, ID string }{"refresh_run", id})
	if e != nil {
		return nil, e
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	r, e := t.WorkflowRun(ctx, id, true)
	if e != nil {
		return nil, e
	}
	if r.Authority != t.AuthorityRevision || r.Root != t.Root {
		return nil, store.ErrUnauthorized
	}
	if e = t.FileAccessible(ctx, r.FileID); e != nil {
		return nil, e
	}
	view, state, reason, e := snapshot(ctx, t, r)
	if e != nil {
		return nil, e
	}
	if e = setProjection(ctx, t, r, state, reason); e != nil {
		return nil, e
	}
	return scheduleResult(t, ctx, key, meaning, id, struct {
		Kind   string   `json:"kind"`
		Status *RunView `json:"status"`
	}{"workflow_run_refresh", view})
}
