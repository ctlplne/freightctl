package checks

import (
	"context"
	"encoding/json"
	"errors"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// Workflow approval supplies a pinned task intent, without release or delivery.
var _ workflow.ProcessingPort = (*Service)(nil)

func projectionWorkflowCurrent(ctx context.Context, t *store.Transaction, d ProjectionDefinition, lock bool) error {
	if d.Workflow == nil {
		return nil
	}
	b := d.Workflow
	c, err := t.Configuration(ctx, false, b.WorkflowID, b.Version, lock)
	if err != nil {
		return err
	}
	if c.Hash != b.Hash || c.State != "approved" || c.ApprovalAuthority != t.AuthorityRevision {
		return store.ErrRevision
	}
	if err = t.CheckProcessingReview(ctx, c.ID, c.Version, c.Hash); err != nil {
		return err
	}
	var definition workflow.Definition
	if workflow.Decode(c.Definition, &definition) != nil {
		return store.ErrState
	}
	definition, err = workflow.Normalize(definition)
	if err != nil || definition.Schema != 3 || definition.Processing == nil {
		return store.ErrState
	}
	_, hash, _ := canonical(definition)
	if hash != c.Hash {
		return store.ErrState
	}
	task := definition.Processing
	_, rules, _ := canonical(task.Definition)
	_, approved, _ := canonical(d.Plan.Projection)
	path := ""
	if d.Plan.Context.Target != nil {
		path = d.Plan.Context.Target.Command.Path
	}
	if task.ID != b.StepID || rules != approved || task.OutputPolicy.ID != d.Plan.Context.Policy.ID || task.OutputPolicy.Version != d.Plan.Context.Policy.Version || task.OutputPolicy.Hash != d.Plan.Context.Policy.Hash || task.Reason != d.Plan.Context.Reason || task.TargetPath != path {
		return store.ErrRevision
	}
	r, err := t.WorkflowRun(ctx, b.RunID, false)
	if err != nil {
		return err
	}
	if r.WorkflowID != b.WorkflowID || r.WorkflowVersion != b.Version || r.WorkflowHash != b.Hash || r.FileID != d.Plan.Context.Source.File.ID || r.Root != t.Root || r.Authority != t.AuthorityRevision || r.StorageID != d.Plan.Context.StorageID || r.State == "cancelled" {
		return store.ErrRevision
	}
	return t.CheckScheduleBinding(ctx, r.ID)
}
func (s *Service) ValidateProcessing(ctx context.Context, t *store.Transaction, task workflow.ProcessingTask, file string) (json.RawMessage, error) {
	view, err := s.processingProjectionPlan(ctx, t, file, task, false)
	if err != nil {
		return nil, err
	}
	if task.OutputPolicy.ID != view.Plan.Context.Policy.ID || task.OutputPolicy.Version != view.Plan.Context.Policy.Version || task.OutputPolicy.Hash != view.Plan.Context.Policy.Hash {
		return nil, store.ErrRevision
	}
	data, _, err := canonical(view)
	return data, err
}

func (s *Service) processingProjectionPlan(ctx context.Context, t *store.Transaction, file string, task workflow.ProcessingTask, lock bool) (*ProjectionPreview, error) {
	ref := store.OnboardingReference{ID: task.OutputPolicy.ID, Version: task.OutputPolicy.Version, Hash: task.OutputPolicy.Hash}
	selected, err := t.ProcessingPolicy(ctx, ref)
	if err != nil {
		return nil, err
	}
	options := ProjectionOptions{Profile: ScopedProjectionProfile, TargetPath: task.TargetPath, Reason: task.Reason, Definition: task.Definition}
	if selected.State == "output_active" {
		options.Profile = ProducerProjectionProfile
		return s.projectionPlanOutput(ctx, t, file, options, lock, &ref)
	}
	return s.projectionPlan(ctx, t, file, options, lock)
}
func (s *Service) StageProcessing(ctx context.Context, t *store.Transaction, run *store.WorkflowRun, task workflow.ProcessingTask) (*store.RecordProjection, error) {
	for _, grant := range []string{"read", "write", "check_run", "workflow_execute"} {
		if err := t.Require(grant); err != nil {
			return nil, err
		}
	}
	if err := s.projectionProposalAdmission(ctx, t); err != nil {
		return nil, err
	}
	if err := t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	view, err := s.processingProjectionPlan(ctx, t, run.FileID, task, true)
	if err != nil {
		return nil, err
	}
	d := ProjectionDefinition{Schema: 2, Plan: view.Plan, Slots: make([]string, 3), Workflow: &store.ProcessingWorkflowBinding{WorkflowID: run.WorkflowID, Version: run.WorkflowVersion, Hash: run.WorkflowHash, RunID: run.ID, StepID: task.ID}}
	if producerProjectionProfile(view.Plan.Profile) {
		d.Schema = view.Plan.Schema
	}
	if err = projectionWorkflowCurrent(ctx, t, d, true); err != nil {
		return nil, err
	}
	for i := range d.Slots {
		d.Slots[i] = secure.NewID()
	}
	data, hash, err := canonical(d)
	if err != nil || len(data) > 32768 {
		return nil, ErrInput
	}
	r := &store.RecordProjection{ID: secure.NewID(), SourceID: run.FileID, Definition: data, Hash: hash, State: "approved", Revision: 1, Result: json.RawMessage(`{}`)}
	if err = t.SaveRecordProjection(ctx, r, 0); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Service) ObserveProcessing(ctx context.Context, t *store.Transaction, run *store.WorkflowRun, b store.WorkflowProcessing) (*workflow.ProcessingObservation, error) {
	if err := t.ScheduleLock(ctx, false); err != nil {
		return nil, err
	}
	if err := projectionActionAuthority(t, ScopedProjectionProfile, ""); err != nil {
		return nil, err
	}
	if s.Custody == nil || s.Custody.Disk == nil {
		return nil, custody.ErrStorageIdentity
	}
	if err := s.Custody.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	if run.Root != t.Root || run.Authority != t.AuthorityRevision || run.StorageID != s.Custody.Disk.Identity() {
		return nil, store.ErrUnauthorized
	}
	r, err := t.RecordProjection(ctx, b.ProjectionID, false)
	if err != nil {
		return nil, err
	}
	d, err := decodeProjection(r)
	if err != nil {
		return nil, err
	}
	if r.Hash != b.Hash || d.Workflow == nil || d.Workflow.RunID != run.ID || r.SourceID != run.FileID {
		return nil, store.ErrState
	}
	v := &workflow.ProcessingObservation{ID: r.ID, Hash: r.Hash, State: r.State, Revision: r.Revision, Attempts: r.Attempts, FileID: r.FileID}
	_, err = s.projectionCurrent(ctx, t, d, false)
	v.Current = err == nil
	if r.State == "completed" {
		c, e := t.FileCheck(ctx, r.FileID, false)
		if e != nil {
			return nil, e
		}
		if c.State == "released" {
			e = t.FileAccessible(ctx, r.FileID)
			if e != nil && !errors.Is(e, store.ErrState) && !errors.Is(e, store.ErrForbidden) && !errors.Is(e, store.ErrNotFound) {
				return nil, e
			}
			v.Released = e == nil
		}
	}
	return v, nil
}

func (s *Service) CancelProcessing(ctx context.Context, t *store.Transaction, b store.WorkflowProcessing) error {
	if err := projectionActionAuthority(t, ScopedProjectionProfile, "workflow_execute"); err != nil {
		return err
	}
	r, err := t.RecordProjection(ctx, b.ProjectionID, true)
	if err != nil {
		return err
	}
	d, err := decodeProjection(r)
	if err != nil {
		return err
	}
	if r.Hash != b.Hash || d.Workflow == nil || d.Workflow.RunID != b.RunID || d.Plan.Context.Root != t.Root || d.Plan.Context.Authority != t.AuthorityRevision {
		return store.ErrRevision
	}
	if r.State == "completed" || r.State == "cancelled" {
		return nil
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if r.State == "running" && (r.LeaseUntil == nil || now.Before(*r.LeaseUntil)) {
		return store.ErrState
	}
	previous := r.Revision
	r.Revision++
	r.State, r.WorkerID, r.LeaseUntil, r.Result = "cancelled", "", nil, json.RawMessage(`{}`)
	return t.SaveRecordProjection(ctx, r, previous)
}
func (s *Service) WorkProcessing(ctx context.Context, scope store.Scope, b store.WorkflowProcessing, revision int64, command string) (*store.RecordProjection, error) {
	view, err := s.GetProjection(ctx, scope, b.ProjectionID)
	if err != nil {
		return nil, err
	}
	definition, err := decodeProjection(view.Projection)
	if err != nil {
		return nil, err
	}
	if view.Projection.Hash != b.Hash || definition.Workflow == nil || definition.Workflow.RunID != b.RunID {
		return nil, store.ErrRevision
	}
	start, err := s.StartProjection(ctx, scope, b.ProjectionID, "wf-projection-start-"+command, ProjectionStartDecision{Hash: b.Hash, Revision: revision})
	if err != nil {
		return nil, err
	}
	var v struct {
		Projection *store.RecordProjection `json:"projection"`
	}
	if json.Unmarshal(start.Resource, &v) != nil || v.Projection == nil {
		return nil, store.ErrState
	}
	a := ProjectionAttempt{ID: b.ProjectionID, Number: v.Projection.Attempts, WorkerID: v.Projection.WorkerID}
	result, err := s.WorkProjection(ctx, scope, "wf-projection-work-"+command, a)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(result.Resource, &v) != nil || v.Projection == nil {
		return nil, store.ErrState
	}
	return v.Projection, nil
}
