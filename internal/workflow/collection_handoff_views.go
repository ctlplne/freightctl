package workflow

import (
	"context"
	"reflect"

	"github.com/ctlplne/freightctl/internal/store"
)

type CollectionHandoffEffect struct {
	Effect
	User           string `json:"user"`
	KeyFingerprint string `json:"key_fingerprint"`
}

// Review metadata remains available after revocation or completion. It contains
// public identities and immutable plans, never payloads or private key paths.
type CollectionHandoffReview struct {
	SourceWorkflow *store.Configuration      `json:"source_workflow"`
	SourcePlan     *ExecutionPlan            `json:"source_plan"`
	SourceEffects  []CollectionHandoffEffect `json:"source_effects"`
	Workflow       *store.Configuration      `json:"workflow"`
	Effects        []CollectionHandoffEffect `json:"effects"`
}

func handoffWorkflow(ctx context.Context, t *store.Transaction, ref Reference) (*store.Configuration, *Definition, error) {
	c, err := t.Configuration(ctx, false, ref.ID, ref.Version, false)
	if err != nil {
		return nil, nil, err
	}
	var d Definition
	if Decode(c.Definition, &d) != nil {
		return nil, nil, store.ErrState
	}
	d, err = Normalize(d)
	if err != nil {
		return nil, nil, err
	}
	_, hash, err := digest(d)
	if err != nil || hash != ref.Hash || c.Hash != hash || d.Schema != 2 || d.Source == nil {
		return nil, nil, store.ErrState
	}
	return c, &d, nil
}

func handoffEffects(ctx context.Context, t *store.Transaction, d *Definition) ([]CollectionHandoffEffect, error) {
	effects, err := historicalWorkflowEffects(ctx, t, d)
	if err != nil {
		return nil, err
	}
	out := make([]CollectionHandoffEffect, 0, len(effects))
	for _, effect := range effects {
		c, err := t.Configuration(ctx, true, effect.Connection.ID, effect.Connection.Version, false)
		if err != nil {
			return nil, err
		}
		v, err := viewConnection(c)
		if err != nil {
			return nil, err
		}
		out = append(out, CollectionHandoffEffect{Effect: effect, User: v.User, KeyFingerprint: v.KeyFingerprint})
	}
	return out, nil
}

func collectionHandoffReview(ctx context.Context, t *store.Transaction, d CollectionHandoffDefinition) (*CollectionHandoffReview, error) {
	source, before, err := handoffWorkflow(ctx, t, d.Source.Workflow)
	if err != nil {
		return nil, err
	}
	target, after, err := handoffWorkflow(ctx, t, d.Workflow)
	if err != nil {
		return nil, err
	}
	run, err := t.WorkflowRun(ctx, d.Source.ID, false)
	if err != nil {
		return nil, err
	}
	if run.WorkflowID != d.Source.Workflow.ID || run.WorkflowVersion != d.Source.Workflow.Version || run.WorkflowHash != d.Source.Workflow.Hash || run.PlanHash != d.Source.PlanHash || !reflect.DeepEqual(before.Source, after.Source) {
		return nil, store.ErrState
	}
	plan, err := storedExecutionPlan(run)
	if err != nil || plan == nil || !reflect.DeepEqual(plan.Facts, d.Plan.Facts) || len(d.Intents) != len(plan.Steps) {
		return nil, store.ErrState
	}
	for index, intent := range d.Intents {
		if intent.Ordinal != index+1 || intent.Step != plan.Steps[index] {
			return nil, store.ErrState
		}
	}
	compiled, err := CompileProgram(*before, plan.Facts)
	if err != nil || !reflect.DeepEqual(compiled, plan) {
		return nil, store.ErrState
	}
	compiled, err = CompileProgram(*after, d.Plan.Facts)
	if err != nil || !reflect.DeepEqual(*compiled, d.Plan) {
		return nil, store.ErrState
	}
	view := &CollectionHandoffReview{SourceWorkflow: source, SourcePlan: plan, Workflow: target}
	view.SourceEffects, err = handoffEffects(ctx, t, before)
	if err != nil {
		return nil, err
	}
	view.Effects, err = handoffEffects(ctx, t, after)
	return view, err
}
