package workflow

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
)

// RunPreview describes a particular immutable input without reserving capacity,
// recording a run or touching file bytes or a peer. Potential effects are the
// approved catalog; selected effects follow the exact compiled plan order.
type RunPreview struct {
	Workflow        Reference      `json:"workflow"`
	Source          store.File     `json:"source"`
	Potential       []Effect       `json:"potential_effects"`
	Selected        []Effect       `json:"selected_effects"`
	Plan            *ExecutionPlan `json:"execution_plan,omitempty"`
	PlanHash        string         `json:"execution_plan_hash,omitempty"`
	ExternalContact bool           `json:"external_contact"`
}

func (s *Service) PreviewRun(ctx context.Context, scope store.Scope, r RunRequest) (*RunPreview, error) {
	if !store.ValidID(r.FileID) {
		return nil, ErrInput
	}
	t, err := s.begin(ctx, scope, "workflow_execute", "read")
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	_, definition, err := approved(ctx, t, r.Workflow)
	if err != nil {
		return nil, err
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
	effects, err := workflowEffects(ctx, t, definition)
	if err != nil {
		return nil, err
	}
	preview := &RunPreview{Workflow: r.Workflow, Source: *source, Potential: effects, Selected: []Effect{}}
	selected := definition.Steps
	if definition.Schema == 2 {
		preview.Plan, selected, err = s.planRun(ctx, t, r, definition, source)
		if err != nil {
			return nil, err
		}
		_, preview.PlanHash, err = digest(preview.Plan)
		if err != nil {
			return nil, err
		}
	} else if definition.Source != nil {
		// A collection preview cannot adopt an unrelated published file. The
		// database checks the original captured claim and all sibling intake.
		if _, err = t.WorkflowRoutingFacts(ctx, r.Workflow.ID, r.Workflow.Version, r.Workflow.Hash, source.ID); err != nil {
			return nil, err
		}
	}
	byID := make(map[string]Effect, len(effects))
	for _, effect := range effects {
		byID[effect.StepID] = effect
	}
	for _, step := range selected {
		effect, ok := byID[step.ID]
		if !ok {
			return nil, store.ErrState
		}
		preview.Selected = append(preview.Selected, effect)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return preview, t.Tx.Commit(ctx)
}
