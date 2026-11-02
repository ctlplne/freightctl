package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionHandoffSelection struct {
	InputID   string    `json:"input_id"`
	SourceRun string    `json:"source_run_id"`
	Workflow  Reference `json:"workflow"`
	Authority int64     `json:"expected_authority_revision"`
}
type CollectionHandoffIntent struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"definition_hash"`
	Step     string `json:"step_id"`
	Ordinal  int    `json:"ordinal"`
}
type CollectionHandoffSource struct {
	ID        string    `json:"id"`
	Revision  int64     `json:"revision"`
	PlanHash  string    `json:"plan_hash"`
	Workflow  Reference `json:"workflow"`
	RoutingID string    `json:"routing_authorization_id,omitempty"`
}
type CollectionHandoffDefinition struct {
	Schema     int                       `json:"schema_version"`
	Profile    string                    `json:"profile"`
	Collection CollectionRoutingJob      `json:"collection"`
	InputID    string                    `json:"input_id"`
	Source     CollectionHandoffSource   `json:"source_run"`
	Intents    []CollectionHandoffIntent `json:"intents"`
	Workflow   Reference                 `json:"workflow"`
	Plan       ExecutionPlan             `json:"plan"`
	PlanHash   string                    `json:"plan_hash"`
	Authority  int64                     `json:"authority_revision"`
	StorageID  string                    `json:"storage_id"`
	Root       string                    `json:"namespace_root"`
}
type CollectionHandoffPreview struct {
	Definition       CollectionHandoffDefinition `json:"definition"`
	Hash             string                      `json:"definition_hash"`
	ExternalContact  bool                        `json:"external_contact"`
	ApprovalRequired bool                        `json:"approval_required"`
}
type CollectionHandoffProposal struct {
	Selection CollectionHandoffSelection `json:"selection"`
	Hash      string                     `json:"definition_hash"`
}
type CollectionHandoffView struct {
	Handoff *store.CollectionHandoff `json:"handoff"`
	Current bool                     `json:"current_bindings"`
	Reason  string                   `json:"binding_reason"`
}

func (s *Service) CollectionHandoffHistory(ctx context.Context, scope store.Scope, job, after string, limit int) (*store.CollectionHandoffPage, error) {
	if !store.ValidID(job) || (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.Collection(ctx, job, false); err != nil {
		return nil, err
	}
	page, err := t.CollectionHandoffHistory(ctx, job, after, limit)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

// Receipt lookup never retries a mutation or relies on still-current bindings.
func (s *Service) CollectionHandoffReceipt(ctx context.Context, scope store.Scope, job, key string) (*Result, error) {
	if !store.ValidID(job) || !keyPattern.MatchString(key) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	id, raw, err := t.CollectionRoutingReceipt(ctx, key)
	if err != nil {
		return nil, err
	}
	if _, err = t.CollectionHandoff(ctx, job, id, false); err != nil {
		return nil, err
	}
	var result struct {
		Kind    string                   `json:"kind"`
		Handoff *store.CollectionHandoff `json:"handoff"`
	}
	if Decode(raw, &result) != nil || result.Kind != "workflow_collection_handoff" || result.Handoff == nil || result.Handoff.ID != id || result.Handoff.JobID != job {
		return nil, store.ErrNotFound
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return &Result{Resource: raw, Replayed: true}, t.Tx.Commit(ctx)
}

func collectionHandoffResult(ctx context.Context, t *store.Transaction, key, meaning string, h *store.CollectionHandoff) (*Result, error) {
	return scheduleResult(t, ctx, key, meaning, h.ID, struct {
		Kind    string                   `json:"kind"`
		Handoff *store.CollectionHandoff `json:"handoff"`
	}{"workflow_collection_handoff", h})
}

func validCollectionHandoffSelection(x CollectionHandoffSelection) bool {
	return store.ValidID(x.InputID) && store.ValidID(x.SourceRun) && store.ValidID(x.Workflow.ID) && x.Workflow.Version > 0 && x.Workflow.Version <= 2147483647 && hashPattern.MatchString(x.Workflow.Hash) && x.Authority > 0
}
func collectionHandoffSelection(d CollectionHandoffDefinition) CollectionHandoffSelection {
	return CollectionHandoffSelection{InputID: d.InputID, SourceRun: d.Source.ID, Workflow: d.Workflow, Authority: d.Authority}
}

func (s *Service) collectionHandoffPreview(ctx context.Context, t *store.Transaction, job string, x CollectionHandoffSelection) (*CollectionHandoffPreview, error) {
	if !store.ValidID(job) || !validCollectionHandoffSelection(x) {
		return nil, ErrInput
	}
	if x.Authority != t.AuthorityRevision {
		return nil, store.ErrRevision
	}
	j, err := t.Collection(ctx, job, false)
	if err != nil {
		return nil, err
	}
	original, err := collectionDefinition(j)
	if err != nil {
		return nil, err
	}
	if err = s.checkStorage(original.StorageID); err != nil {
		return nil, err
	}
	input, err := t.CollectionInput(ctx, x.InputID, true)
	if err != nil {
		return nil, err
	}
	if input.JobID != job || input.State != "queued" || input.RunID == nil || input.FileID == nil {
		return nil, store.ErrState
	}
	run, err := t.WorkflowRun(ctx, x.SourceRun, true)
	if err != nil {
		return nil, err
	}
	if run.State != "queued" && run.State != "running" && run.State != "attention" {
		return nil, store.ErrState
	}
	steps, err := t.WorkflowSteps(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	if len(steps) == 0 || len(steps) > 16 {
		return nil, store.ErrState
	}
	for _, step := range steps {
		intent, err := t.Delivery(ctx, step.DeliveryID, true)
		if err != nil {
			return nil, err
		}
		if intent.State != "queued" || intent.Attempts != 0 || intent.Fence != 0 || intent.LeaseOwner != "" || intent.LeaseUntil != nil {
			return nil, store.ErrState
		}
		if artifact, err := t.DeliveryCiphertext(ctx, intent.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		} else if artifact != nil {
			return nil, store.ErrState
		}
	}
	if err = t.FileAccessible(ctx, *input.FileID); err != nil {
		return nil, err
	}
	_, target, err := approved(ctx, t, x.Workflow)
	if err != nil {
		return nil, err
	}
	raw, err := t.CollectionHandoffDefinition(ctx, job, input.ID, run.ID, x.Workflow.ID, x.Workflow.Version, x.Workflow.Hash)
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<10 {
		return nil, store.ErrLimit
	}
	var d CollectionHandoffDefinition
	if Decode(raw, &d) != nil || d.Schema != 1 || d.Profile != "untouched-collected-handoff-v1" || !reflect.DeepEqual(collectionHandoffSelection(d), x) {
		return nil, store.ErrState
	}
	// PostgreSQL supplies original captured facts. Go independently compiles the
	// target program, so a proposal cannot invent a file, branch or recipient.
	plan, err := CompileProgram(*target, d.Plan.Facts)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(*plan, d.Plan) {
		return nil, store.ErrState
	}
	_, planHash, err := digest(plan)
	if err != nil || planHash != d.PlanHash {
		return nil, store.ErrState
	}
	raw, hash, err := digest(d)
	if err != nil {
		return nil, err
	}
	if len(raw) > 32<<10 {
		return nil, store.ErrLimit
	}
	return &CollectionHandoffPreview{Definition: d, Hash: hash, ApprovalRequired: true}, nil
}

func (s *Service) PreviewCollectionHandoff(ctx context.Context, scope store.Scope, job string, x CollectionHandoffSelection) (*CollectionHandoffPreview, error) {
	if !store.ValidID(job) || !validCollectionHandoffSelection(x) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	p, err := s.collectionHandoffPreview(ctx, t, job, x)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return p, t.Tx.Commit(ctx)
}

func (s *Service) ProposeCollectionHandoff(ctx context.Context, scope store.Scope, job, key string, x CollectionHandoffProposal) (*Result, error) {
	if !store.ValidID(job) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || !validCollectionHandoffSelection(x.Selection) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "workflow_manage", "read", "write", "list")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, Job string
		Request   CollectionHandoffProposal
	}{"collection_handoff_propose", job, x})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	p, err := s.collectionHandoffPreview(ctx, t, job, x.Selection)
	if err != nil {
		return nil, err
	}
	if p.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	raw, _, err := digest(p.Definition)
	if err != nil {
		return nil, err
	}
	h := &store.CollectionHandoff{ID: secure.NewID(), JobID: job, InputID: x.Selection.InputID, SourceRunID: x.Selection.SourceRun, PlannedRunID: secure.NewID(), Definition: raw, Hash: p.Hash, State: "proposed", Revision: 1}
	if err = t.SaveCollectionHandoff(ctx, h, 0); err != nil {
		return nil, err
	}
	return collectionHandoffResult(ctx, t, key, meaning, h)
}

func (s *Service) DecideCollectionHandoff(ctx context.Context, scope store.Scope, job, id, key, action string, x Decision) (*Result, error) {
	if !store.ValidID(job) || !store.ValidID(id) || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 || (action != "approve" && action != "cancel" && action != "execute") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if action == "approve" {
		err = t.Require("workflow_approve")
	} else {
		err = t.Require("workflow_manage")
	}
	if err != nil {
		return nil, err
	}
	_, meaning, _ := digest(struct {
		Kind, Job, ID, Action string
		Decision              Decision
	}{"collection_handoff_decide", job, id, action, x})
	if prior, err := replay(t, ctx, key, meaning); err != nil || prior != nil {
		return prior, err
	}
	h, err := t.CollectionHandoff(ctx, job, id, true)
	if err != nil {
		return nil, err
	}
	if h.Hash != x.Hash || h.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	if (action == "approve" && h.State != "proposed") || (action == "execute" && h.State != "approved") || (action == "cancel" && h.State != "proposed" && h.State != "approved") {
		return nil, store.ErrState
	}
	previous := h.Revision
	if action == "cancel" {
		h.State = "cancelled"
	} else {
		for _, grant := range []string{"write", "list"} {
			if err = t.Require(grant); err != nil {
				return nil, err
			}
		}
		var d CollectionHandoffDefinition
		if Decode(h.Definition, &d) != nil {
			return nil, store.ErrState
		}
		p, err := s.collectionHandoffPreview(ctx, t, job, collectionHandoffSelection(d))
		if err != nil {
			return nil, err
		}
		if p.Hash != h.Hash {
			return nil, store.ErrRevision
		}
		if action == "approve" {
			h.State, h.ApprovalAuthority = "approved", t.AuthorityRevision
		} else {
			if h.ApprovalAuthority != t.AuthorityRevision {
				return nil, store.ErrRevision
			}
			for _, old := range d.Intents {
				intent, err := t.Delivery(ctx, old.ID, true)
				if err != nil {
					return nil, err
				}
				prior := intent.Revision
				intent.State = "cancelled"
				intent.Observation, _ = json.Marshal(map[string]string{"code": "collection_handoff", "handoff_id": h.ID})
				intent.Revision++
				if err = t.SaveDelivery(ctx, intent, prior); err != nil {
					return nil, err
				}
			}
			run, err := t.WorkflowRun(ctx, d.Source.ID, true)
			if err != nil {
				return nil, err
			}
			if err = setProjection(ctx, t, run, "cancelled", "collection_handoff"); err != nil {
				return nil, err
			}
			_, workflow, err := approved(ctx, t, d.Workflow)
			if err != nil {
				return nil, err
			}
			file, err := t.File(ctx, run.FileID)
			if err != nil {
				return nil, err
			}
			if _, err = s.stageRunBound(ctx, t, RunRequest{Workflow: d.Workflow, FileID: file.ID}, workflow, file, d.StorageID, "", h.PlannedRunID); err != nil {
				return nil, err
			}
			h.State = "completed"
		}
	}
	h.Revision++
	if err = t.SaveCollectionHandoff(ctx, h, previous); err != nil {
		return nil, err
	}
	return collectionHandoffResult(ctx, t, key, meaning, h)
}

func (s *Service) CollectionHandoffStatus(ctx context.Context, scope store.Scope, job, id string) (*CollectionHandoffView, error) {
	if !store.ValidID(job) || !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.collectionBegin(ctx, scope, "workflow_execute", "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	h, err := t.CollectionHandoff(ctx, job, id, false)
	if err != nil {
		return nil, err
	}
	view := &CollectionHandoffView{Handoff: h, Reason: h.State}
	if h.State == "proposed" || h.State == "approved" {
		var d CollectionHandoffDefinition
		if Decode(h.Definition, &d) != nil {
			return nil, store.ErrState
		}
		raw, err := t.CollectionHandoffDefinition(ctx, job, d.InputID, d.Source.ID, d.Workflow.ID, d.Workflow.Version, d.Workflow.Hash)
		if err != nil && !bindingChanged(err) {
			return nil, err
		}
		if err == nil {
			var current CollectionHandoffDefinition
			if Decode(raw, &current) != nil {
				return nil, store.ErrState
			}
			_, hash, err := digest(current)
			if err != nil {
				return nil, err
			}
			view.Current = hash == h.Hash
		}
		if view.Current {
			view.Reason = "current"
		} else {
			view.Reason = "binding_changed"
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return view, t.Tx.Commit(ctx)
}
