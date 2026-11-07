package workflow

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/ctlplne/freightctl/internal/store"
)

type Difference struct {
	WorkflowID        string     `json:"workflow_id"`
	FromVersion       int        `json:"from_version"`
	ToVersion         int        `json:"to_version"`
	FromHash          string     `json:"from_hash"`
	ToHash            string     `json:"to_hash"`
	Before            Definition `json:"before"`
	After             Definition `json:"after"`
	NameChanged       bool       `json:"name_changed"`
	OrderChanged      bool       `json:"order_changed"`
	SourceChanged     bool       `json:"source_changed,omitempty"`
	ProgramChanged    bool       `json:"program_changed,omitempty"`
	ProcessingChanged bool       `json:"processing_changed,omitempty"`
	Added             []string   `json:"added_steps"`
	Removed           []string   `json:"removed_steps"`
	Changed           []string   `json:"changed_steps"`
}

func (s *Service) Diff(ctx context.Context, scope store.Scope, id string, from, to int) (*Difference, error) {
	t, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	before, err := t.Configuration(ctx, false, id, from, false)
	if err != nil {
		return nil, err
	}
	after, err := t.Configuration(ctx, false, id, to, false)
	if err != nil {
		return nil, err
	}
	if err = workflowConfigurationScope(t, before); err != nil {
		return nil, err
	}
	if err = workflowConfigurationScope(t, after); err != nil {
		return nil, err
	}
	d := &Difference{WorkflowID: id, FromVersion: from, ToVersion: to, FromHash: before.Hash, ToHash: after.Hash, Added: []string{}, Removed: []string{}, Changed: []string{}}
	if err = json.Unmarshal(before.Definition, &d.Before); err != nil {
		return nil, store.ErrState
	}
	if err = json.Unmarshal(after.Definition, &d.After); err != nil {
		return nil, store.ErrState
	}
	d.NameChanged = d.Before.Name != d.After.Name
	d.SourceChanged = !reflect.DeepEqual(d.Before.Source, d.After.Source)
	d.ProgramChanged = !reflect.DeepEqual(d.Before.Program, d.After.Program)
	d.ProcessingChanged = !reflect.DeepEqual(d.Before.Processing, d.After.Processing)
	old, new := map[string]Step{}, map[string]Step{}
	for _, step := range d.Before.Steps {
		old[step.ID] = step
	}
	for _, step := range d.After.Steps {
		new[step.ID] = step
	}
	for _, step := range d.Before.Steps {
		if _, ok := new[step.ID]; !ok {
			d.Removed = append(d.Removed, step.ID)
		}
	}
	for _, step := range d.After.Steps {
		if prior, ok := old[step.ID]; !ok {
			d.Added = append(d.Added, step.ID)
		} else if !reflect.DeepEqual(prior, step) {
			d.Changed = append(d.Changed, step.ID)
		}
	}
	if len(d.Before.Steps) != len(d.After.Steps) {
		d.OrderChanged = true
	} else {
		for i, step := range d.Before.Steps {
			if step.ID != d.After.Steps[i].ID {
				d.OrderChanged = true
				break
			}
		}
	}
	return d, t.Tx.Commit(ctx)
}
func (s *Service) Cancel(ctx context.Context, scope store.Scope, id, key string, decision Decision) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(decision.Hash) || decision.Revision < 1 {
		return nil, ErrInput
	}
	t, err := s.beginWorkflow(ctx, scope, "workflow_execute", "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, _ := digest(struct {
		Kind, ID string
		Decision Decision
	}{"cancel_run", id, decision})
	data, err := t.WorkflowReplay(ctx, key, meaning)
	if err != nil {
		return nil, err
	}
	r, err := t.WorkflowRun(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if r.Authority != t.AuthorityRevision || r.Root != t.Root {
		return nil, store.ErrUnauthorized
	}
	binding, err := s.processingBinding(ctx, t, r)
	if err != nil {
		return nil, err
	}
	if binding != nil {
		if _, err = s.Processor.ObserveProcessing(ctx, t, r, *binding); err != nil {
			return nil, err
		}
		if data != nil {
			return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
		}
		if r.Revision != decision.Revision || r.WorkflowHash != decision.Hash {
			return nil, store.ErrRevision
		}
		if r.State == "succeeded" || r.State == "cancelled" {
			return nil, store.ErrState
		}
		if err = s.Processor.CancelProcessing(ctx, t, *binding); err != nil {
			return nil, err
		}
		if err = setProjection(ctx, t, r, "cancelled", "operator_cancelled"); err != nil {
			return nil, err
		}
		view, _, _, err := s.runSnapshot(ctx, t, r)
		if err != nil {
			return nil, err
		}
		return result(t, ctx, key, meaning, id, view)
	}
	if err = t.FileAccessible(ctx, r.FileID); err != nil {
		return nil, err
	}
	if data != nil {
		return &Result{Resource: data, Replayed: true}, t.Tx.Commit(ctx)
	}
	if r.Revision != decision.Revision || r.WorkflowHash != decision.Hash {
		return nil, store.ErrRevision
	}
	if r.State == "succeeded" || r.State == "cancelled" || r.State == "kept_local" {
		return nil, store.ErrState
	}
	steps, err := t.WorkflowSteps(ctx, id)
	if err != nil {
		return nil, err
	}
	unfinished := false
	for _, step := range steps {
		d, err := t.Delivery(ctx, step.DeliveryID, true)
		if err != nil {
			return nil, err
		}
		if d.State != "succeeded" {
			unfinished = true
		}
		switch d.State {
		case "staging", "publishing", "ambiguous":
			return nil, store.ErrState
		case "draft", "queued", "retry":
			previous := d.Revision
			d.Revision++
			d.State = "cancelled"
			d.Observation = json.RawMessage(`{"code":"workflow_cancelled"}`)
			if err = t.SaveDelivery(ctx, d, previous); err != nil {
				return nil, err
			}
		}
	}
	if !unfinished {
		return nil, store.ErrState
	}
	if err = setProjection(ctx, t, r, "cancelled", "operator_cancelled"); err != nil {
		return nil, err
	}
	view, _, _, err := snapshot(ctx, t, r)
	if err != nil {
		return nil, err
	}
	return result(t, ctx, key, meaning, id, view)
}
