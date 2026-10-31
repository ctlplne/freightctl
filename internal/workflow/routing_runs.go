package workflow

import (
	"context"
	"reflect"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Service) planRun(ctx context.Context, t *store.Transaction, r RunRequest, d *Definition, file *store.File) (*ExecutionPlan, []Step, error) {
	raw, err := t.WorkflowRoutingFacts(ctx, r.Workflow.ID, r.Workflow.Version, r.Workflow.Hash, file.ID)
	if err != nil {
		return nil, nil, err
	}
	var facts RoutingFacts
	if Decode(raw, &facts) != nil || facts.File != *file {
		return nil, nil, store.ErrState
	}
	plan, err := CompileProgram(*d, facts)
	if err != nil {
		return nil, nil, err
	}
	byID := map[string]Step{}
	for _, step := range d.Steps {
		byID[step.ID] = step
	}
	selected := make([]Step, 0, len(plan.Steps))
	for _, id := range plan.Steps {
		step, ok := byID[id]
		if !ok {
			return nil, nil, store.ErrState
		}
		selected = append(selected, step)
	}
	return plan, selected, nil
}
func storedExecutionPlan(r *store.WorkflowRun) (*ExecutionPlan, error) {
	if len(r.Plan) == 0 {
		if r.PlanHash != "" || r.State == "kept_local" {
			return nil, store.ErrState
		}
		return nil, nil
	}
	var p ExecutionPlan
	if Decode(r.Plan, &p) != nil || p.Schema != 1 || p.Facts.File != r.Source || len(p.Steps) > 16 || len(p.Decisions) < 1 || len(p.Decisions) > maxProgramVisits {
		return nil, store.ErrState
	}
	_, hash, err := digest(p)
	if err != nil || hash != r.PlanHash {
		return nil, store.ErrState
	}
	seen := map[string]bool{}
	for _, id := range p.Steps {
		if !stepPattern.MatchString(id) || seen[id] {
			return nil, store.ErrState
		}
		seen[id] = true
	}
	if (len(p.Steps) == 0) != (p.LocalReason != "") || p.LocalReason != "" && !stepPattern.MatchString(p.LocalReason) || (r.State == "kept_local") != (p.LocalReason != "") {
		return nil, store.ErrState
	}
	return &p, nil
}
func planStepsMatch(plan *ExecutionPlan, steps []store.WorkflowStep) bool {
	if plan == nil {
		return len(steps) > 0
	}
	ids := make([]string, 0, len(steps))
	for _, s := range steps {
		ids = append(ids, s.ID)
	}
	return reflect.DeepEqual(ids, plan.Steps)
}

// Compile every remaining sibling before capacity can split admission. A full
// send queue may delay work, but cannot hide an undecidable later input.
func (s *Service) collectionRoutingCounts(ctx context.Context, t *store.Transaction, j *store.CollectionJob, ref Reference, w *Definition, inputs []store.CollectionInput, authorization *CollectionRoutingDefinition) (map[string]int, error) {
	counts := map[string]int{}
	for _, input := range inputs {
		if input.JobID != j.ID || input.State != "accepted" {
			continue
		}
		if input.FileID == nil {
			return nil, store.ErrState
		}
		if err := t.FileAccessible(ctx, *input.FileID); err != nil {
			return nil, err
		}
		entry, err := t.Entry(ctx, input.Target)
		if err != nil {
			return nil, err
		}
		if entry.Kind != "file" || entry.FileID != *input.FileID {
			return nil, store.ErrState
		}
		file, err := t.File(ctx, *input.FileID)
		if err != nil {
			return nil, err
		}
		plan, selected, err := s.planRun(ctx, t, RunRequest{Workflow: ref, FileID: file.ID}, w, file)
		if err != nil {
			return nil, err
		}
		if authorization != nil {
			_, hash, err := digest(plan)
			if err != nil {
				return nil, err
			}
			matched := false
			for _, binding := range authorization.Inputs {
				if binding.InputID == input.ID && binding.FileID == file.ID && binding.PlanHash == hash {
					matched = true
					break
				}
			}
			if !matched {
				return nil, store.ErrRevision
			}
		}
		counts[input.ID] = len(selected)
	}
	return counts, nil
}
