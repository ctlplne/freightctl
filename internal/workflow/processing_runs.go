package workflow

import (
	"context"
	"encoding/json"
	"errors"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// Only callers that explicitly distinguish processing from legacy delivery use
// this entry point. All other workflow management keeps the legacy root gate.
func (s *Service) beginWorkflow(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, err := s.Custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if err = t.Require(g); err != nil {
			t.Tx.Rollback(ctx)
			return nil, err
		}
	}
	return t, nil
}
func workflowDefinitionScope(t *store.Transaction, d Definition) error {
	if t.Root != "/" && d.Schema != 3 {
		return store.ErrForbidden
	}
	return nil
}
func workflowConfigurationScope(t *store.Transaction, c *store.Configuration) error {
	if t.Root == "/" {
		return nil
	}
	var d Definition
	if Decode(c.Definition, &d) != nil {
		return store.ErrState
	}
	return workflowDefinitionScope(t, d)
}
func (s *Service) processingBinding(ctx context.Context, t *store.Transaction, r *store.WorkflowRun) (*store.WorkflowProcessing, error) {
	c, err := t.Configuration(ctx, false, r.WorkflowID, r.WorkflowVersion, false)
	if err != nil {
		return nil, err
	}
	if err = workflowConfigurationScope(t, c); err != nil {
		return nil, err
	}
	var d Definition
	if Decode(c.Definition, &d) != nil {
		return nil, store.ErrState
	}
	b, err := t.WorkflowProcessing(ctx, r.ID)
	if d.Schema != 3 {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrState
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Processor == nil {
		return nil, store.ErrState
	}
	return b, nil
}
func (s *Service) runSnapshot(ctx context.Context, t *store.Transaction, r *store.WorkflowRun) (*RunView, string, string, error) {
	b, err := s.processingBinding(ctx, t, r)
	if err != nil {
		return nil, "", "", err
	}
	if b == nil {
		if err = t.FileAccessible(ctx, r.FileID); err != nil {
			return nil, "", "", err
		}
		return snapshot(ctx, t, r)
	}
	if err = s.checkStorage(r.StorageID); err != nil {
		return nil, "", "", err
	}
	p, err := s.Processor.ObserveProcessing(ctx, t, r, *b)
	if err != nil {
		return nil, "", "", err
	}
	return processingSnapshotResult(r, p)
}
func processingSnapshotResult(r *store.WorkflowRun, p *ProcessingObservation) (*RunView, string, string, error) {
	if p == nil || !store.ValidID(p.ID) || !hashPattern.MatchString(p.Hash) || p.Revision < 1 || p.Attempts < 0 || p.Attempts > 3 {
		return nil, "", "", store.ErrState
	}
	state, reason := "queued", "awaiting_worker"
	switch p.State {
	case "approved":
	case "running":
		state, reason = "running", "processing_in_progress"
	case "failed":
		state, reason = "attention", "processing_failed"
	case "cancelled":
		state, reason = "attention", "processing_cancelled"
	case "completed":
		if !store.ValidID(p.FileID) || p.Attempts < 1 {
			return nil, "", "", store.ErrState
		}
		state, reason = "attention", "output_held"
		if p.Released {
			state, reason = "succeeded", "transformed_output_released"
		}
	default:
		return nil, "", "", store.ErrState
	}
	if p.State != "completed" && p.State != "cancelled" && !p.Current {
		state, reason = "attention", "processing_binding_changed"
	}
	if r.State == "cancelled" {
		state, reason = "cancelled", "operator_cancelled"
	}
	v := &RunView{Run: r, Steps: []RunStepView{}, Processing: p, ObservedState: state, ObservedReason: reason}
	return v, state, reason, nil
}
func (s *Service) runProcessing(ctx context.Context, t *store.Transaction, key string, request RunRequest) (*Result, error) {
	if s.Processor == nil {
		return nil, store.ErrState
	}
	for _, g := range []string{"read", "write", "check_run", "workflow_execute"} {
		if err := t.Require(g); err != nil {
			return nil, err
		}
	}
	if s.Custody.Disk == nil {
		return nil, store.ErrState
	}
	storage := s.Custody.Disk.Identity()
	if err := s.checkStorage(storage); err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind      string
		Request   RunRequest
		Authority int64
		Storage   string
	}{"create_run", request, t.AuthorityRevision, storage})
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	if data != nil {
		var original store.WorkflowRun
		if json.Unmarshal(data, &original) != nil || original.WorkflowID != request.Workflow.ID || original.WorkflowVersion != request.Workflow.Version || original.WorkflowHash != request.Workflow.Hash || original.FileID != request.FileID || original.Root != t.Root || original.Authority != t.AuthorityRevision || original.StorageID != storage {
			return nil, store.ErrState
		}
		r, err := t.WorkflowRun(ctx, original.ID, false)
		if err != nil {
			return nil, err
		}
		if _, _, _, err = s.runSnapshot(ctx, t, r); err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	_, d, err := approved(ctx, t, request.Workflow)
	if err != nil {
		return nil, err
	}
	if d.Schema != 3 || d.Processing == nil {
		return nil, store.ErrState
	}
	f, err := t.File(ctx, request.FileID)
	if err != nil {
		return nil, err
	}
	if f.Size > s.Custody.MaxFile {
		return nil, store.ErrLimit
	}
	r, err := s.stageProcessingRun(ctx, t, request, d, f, storage)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, r.ID, r)
}

// Manual runs and calendars stage the same owned run,intent and membership in
// their caller's transaction. The schedule receipt is committed by its caller.
func (s *Service) stageProcessingRun(ctx context.Context, t *store.Transaction, request RunRequest, d *Definition, f *store.File, storage string) (*store.WorkflowRun, error) {
	r := &store.WorkflowRun{ID: secure.NewID(), WorkflowID: request.Workflow.ID, WorkflowVersion: request.Workflow.Version, WorkflowHash: request.Workflow.Hash, FileID: f.ID, Source: *f, StorageID: storage, Root: t.Root, Authority: t.AuthorityRevision, State: "queued", Reason: "awaiting_worker", Revision: 1}
	if err := t.SaveWorkflowRun(ctx, r, 0); err != nil {
		return nil, err
	}
	p, err := s.Processor.StageProcessing(ctx, t, r, *d.Processing)
	if err != nil {
		return nil, err
	}
	if err = t.BindWorkflowProcessing(ctx, &store.WorkflowProcessing{RunID: r.ID, ProjectionID: p.ID, Hash: p.Hash}); err != nil {
		return nil, err
	}
	return r, nil
}
func validateProcessingDispatch(d Dispatch, b store.WorkflowProcessing, step string) error {
	if d.RunID != b.RunID || d.ProjectionID != b.ProjectionID || d.ProjectionHash != b.Hash || d.StepID != step || d.DeliveryID != "" || d.ProjectionRevision < 1 {
		return store.ErrState
	}
	return nil
}
func (s *Service) prepareProcessing(ctx context.Context, t *store.Transaction, r *store.WorkflowRun, b store.WorkflowProcessing, key, meaning string, data json.RawMessage) (*Dispatch, bool, error) {
	for _, g := range []string{"write", "check_run"} {
		if err := t.Require(g); err != nil {
			return nil, false, err
		}
	}
	_, definition, err := approved(ctx, t, Reference{ID: r.WorkflowID, Version: r.WorkflowVersion, Hash: r.WorkflowHash})
	if err != nil {
		return nil, false, err
	}
	if definition.Processing == nil {
		return nil, false, store.ErrState
	}
	p, err := s.Processor.ObserveProcessing(ctx, t, r, b)
	if err != nil {
		return nil, false, err
	}
	if data != nil {
		var d Dispatch
		if json.Unmarshal(data, &d) != nil || validateProcessingDispatch(d, b, definition.Processing.ID) != nil {
			return nil, false, store.ErrState
		}
		if d.ProjectionRevision > p.Revision || (d.ObserveOnly && p.State != "completed") {
			return nil, false, store.ErrState
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, false, err
		}
		return &d, true, t.Tx.Commit(ctx)
	}
	if r.State == "succeeded" || r.State == "cancelled" || p.State == "cancelled" {
		return nil, false, store.ErrState
	}
	if !p.Current && p.State != "completed" {
		return nil, false, store.ErrRevision
	}
	d := &Dispatch{RunID: r.ID, StepID: definition.Processing.ID, ProjectionID: b.ProjectionID, ProjectionHash: b.Hash, ProjectionRevision: p.Revision, ObserveOnly: p.State == "completed"}
	state, reason := "running", "processing_prepared"
	if d.ObserveOnly {
		_, state, reason, err = processingSnapshotResult(r, p)
		if err != nil {
			return nil, false, err
		}
	}
	if err = setProjection(ctx, t, r, state, reason); err != nil {
		return nil, false, err
	}
	if err = t.WorkflowReceipt(ctx, key, meaning, r.ID, d); err != nil {
		return nil, false, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, false, err
	}
	return d, false, t.Tx.Commit(ctx)
}
