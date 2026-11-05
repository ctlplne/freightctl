package api

import (
	"encoding/json"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func onwardRunFacts(run *store.WorkflowRun) (map[string]any, error) {
	if run == nil || !store.ValidID(run.ID) || !store.ValidID(run.FileID) || !store.ValidID(run.WorkflowID) || run.Source.ID != run.FileID {
		return nil, store.ErrIsolation
	}
	return map[string]any{"run_id": run.ID, "workflow": workflow.Reference{ID: run.WorkflowID, Version: run.WorkflowVersion, Hash: run.WorkflowHash}, "artifact": store.ExchangeArtifact{ID: run.Source.ID, Size: run.Source.Size, SHA256: run.Source.SHA256, Policy: run.Source.Policy}, "receiver_persistence": "unknown", "business_processing": "unknown"}, nil
}
func mcpOnwardAcceptance(result *workflow.Result) (map[string]any, error) {
	if result == nil {
		return nil, store.ErrIsolation
	}
	var receipt workflow.OnwardRunReceipt
	if json.Unmarshal(result.Resource, &receipt) != nil || receipt.Profile != workflow.OnwardProfile || len(receipt.ReviewHash) != 64 || receipt.WorkflowRevision < 1 {
		return nil, store.ErrIsolation
	}
	run := receipt.WorkflowRun
	facts, err := onwardRunFacts(&run)
	if err != nil {
		return nil, err
	}
	facts["review_hash"] = receipt.ReviewHash
	facts["accepted_run_state"] = run.State
	facts["current_state"] = "not-checked"
	facts["acceptance"] = "recorded-run-and-intents-only"
	facts["replayed"] = result.Replayed
	return facts, nil
}
func mcpOnwardStatus(view *workflow.RunView) (map[string]any, error) {
	if view == nil {
		return nil, store.ErrIsolation
	}
	facts, err := onwardRunFacts(view.Run)
	if err != nil {
		return nil, err
	}
	facts["observed_state"] = view.ObservedState
	facts["reason_sha256"] = secure.Digest([]byte(view.ObservedReason))
	steps := make([]map[string]any, 0, len(view.Steps))
	for _, step := range view.Steps {
		if !store.ValidID(step.DeliveryID) {
			return nil, store.ErrIsolation
		}
		steps = append(steps, map[string]any{"ordinal": step.Ordinal, "delivery_id": step.DeliveryID, "state": step.State, "observation_sha256": secure.Digest(step.Observation)})
	}
	facts["steps"] = steps
	return facts, nil
}
