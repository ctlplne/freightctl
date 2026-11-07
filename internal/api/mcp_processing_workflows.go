package api

import (
	"context"
	"encoding/json"
	"slices"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

const mcpProcessingWorkflowProfile = "typed-record-workflow-v1"

func processingConfiguration(c *store.Configuration) error {
	if c == nil {
		return store.ErrIsolation
	}
	var d workflow.Definition
	if workflow.Decode(c.Definition, &d) != nil {
		return store.ErrIsolation
	}
	d, err := workflow.Normalize(d)
	if err != nil {
		return err
	}
	if d.Schema != 3 || d.Processing == nil || len(d.Steps) != 0 {
		return store.ErrForbidden
	}
	wire, err := json.Marshal(d)
	if err != nil || secure.Digest(wire) != c.Hash {
		return store.ErrIsolation
	}
	return nil
}
func mcpProcessingRun(r *store.WorkflowRun) (map[string]any, error) {
	if r == nil || !store.ValidID(r.ID) || !store.ValidID(r.WorkflowID) || r.WorkflowVersion < 1 || !mcpUploadDigest.MatchString(r.WorkflowHash) || r.Source.ID != r.FileID || !store.ValidID(r.FileID) || r.Source.Size < 0 || !mcpUploadDigest.MatchString(r.Source.SHA256) || !store.ValidArtifactPolicy(r.Source.Policy) || len(r.Plan) != 0 || r.PlanHash != "" || r.RoutingID != "" || r.Revision < 1 || !slices.Contains([]string{"queued", "running", "attention", "succeeded", "cancelled"}, r.State) {
		return nil, store.ErrIsolation
	}
	return map[string]any{"profile": mcpProcessingWorkflowProfile, "run_id": r.ID, "workflow": workflow.Reference{ID: r.WorkflowID, Version: r.WorkflowVersion, Hash: r.WorkflowHash}, "source": store.ExchangeArtifact{ID: r.FileID, Size: r.Source.Size, SHA256: r.Source.SHA256, Policy: r.Source.Policy}, "recorded_state": r.State, "revision": r.Revision, "external_contact": false, "delivery_intents": 0, "receiver_persistence": "not-applicable", "business_processing": "not-proven"}, nil
}
func mcpProcessingAcceptance(result *workflow.Result) (map[string]any, error) {
	if result == nil {
		return nil, store.ErrIsolation
	}
	var r store.WorkflowRun
	if json.Unmarshal(result.Resource, &r) != nil || r.State != "queued" || r.Revision != 1 {
		return nil, store.ErrIsolation
	}
	value, err := mcpProcessingRun(&r)
	if err != nil {
		return nil, err
	}
	value["observation"] = "original-command-receipt"
	value["current"] = "not-checked"
	value["acceptance"] = "recorded-run-and-processing-intent-only"
	value["replayed"] = result.Replayed
	return value, nil
}
func mcpProcessingStatus(view *workflow.RunView, observation string) (map[string]any, error) {
	if view == nil || view.Processing == nil || len(view.Steps) != 0 {
		return nil, store.ErrForbidden
	}
	p := view.Processing
	if !store.ValidID(p.ID) || !mcpUploadDigest.MatchString(p.Hash) || p.Revision < 1 || p.Attempts < 0 || p.Attempts > 3 || !slices.Contains([]string{"approved", "running", "failed", "cancelled", "completed"}, p.State) || (p.State == "completed") != store.ValidID(p.FileID) || p.Released && p.State != "completed" {
		return nil, store.ErrIsolation
	}
	if !slices.Contains([]string{"queued", "running", "attention", "succeeded", "cancelled"}, view.ObservedState) || !slices.Contains([]string{"awaiting_worker", "processing_in_progress", "processing_failed", "processing_cancelled", "output_held", "transformed_output_released", "processing_binding_changed", "operator_cancelled"}, view.ObservedReason) {
		return nil, store.ErrIsolation
	}
	if view.ObservedState == "succeeded" && (!p.Released || p.State != "completed") {
		return nil, store.ErrIsolation
	}
	value, err := mcpProcessingRun(view.Run)
	if err != nil {
		return nil, err
	}
	var current any = p.Current
	if observation == "original-command-receipt" {
		current = "not-checked"
	}
	value["observation"] = observation
	value["observed_state"] = view.ObservedState
	value["observed_reason"] = view.ObservedReason
	value["processing"] = map[string]any{"projection_id": p.ID, "definition_hash": p.Hash, "state": p.State, "revision": p.Revision, "attempts": p.Attempts, "output_file_id": p.FileID, "output_released_at_observation": p.Released, "current": current}
	return value, nil
}
func (s *Server) mcpProcessingWorkflowControl(ctx context.Context, scope store.Scope, name string, args mcpToolArguments) (any, error) {
	if name == "freightctl.processing_contracts" {
		if args.OutputPolicy != nil {
			return s.Checks.DescribeProcessingOutput(ctx, scope, args.File, *args.OutputPolicy)
		}
		return s.Checks.DescribeProcessing(ctx, scope, args.File)
	}
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	if name == "freightctl.start_processing_workflow" {
		var request workflow.RunRequest
		if workflow.Decode(args.Request, &request) != nil {
			return nil, workflow.ErrInput
		}
		cfg, err := service.Configuration(ctx, scope, request.Workflow.ID, request.Workflow.Version)
		if err != nil {
			return nil, err
		}
		if err = processingConfiguration(cfg); err != nil {
			return nil, err
		}
		result, err := service.Run(ctx, scope, args.Key, request)
		if err != nil {
			return nil, err
		}
		return mcpProcessingAcceptance(result)
	}
	view, err := service.Status(ctx, scope, args.Run)
	if err != nil {
		return nil, err
	}
	if _, err = mcpProcessingStatus(view, "current-observation"); err != nil {
		return nil, err
	}
	switch name {
	case "freightctl.inspect_processing_workflow":
		return mcpProcessingStatus(view, "current-observation")
	case "freightctl.work_processing_workflow":
		result, err := service.Work(ctx, scope, args.Run, args.Key)
		if err != nil {
			return nil, err
		}
		status, err := mcpProcessingStatus(result.Status, "current-observation")
		if err != nil {
			return nil, err
		}
		value := map[string]any{"profile": mcpProcessingWorkflowProfile, "status": status, "replayed": result.Replayed}
		if result.Processing != nil {
			if result.Processing.ID != result.Dispatch.ProjectionID || result.Processing.Hash != result.Dispatch.ProjectionHash || result.Dispatch.RunID != args.Run || result.Dispatch.DeliveryID != "" {
				return nil, store.ErrIsolation
			}
			value["attempt"], err = mcpProjectionProfileFacts(result.Processing, result.Replayed, false, "original-command-receipt", args.Run)
			if err != nil {
				return nil, err
			}
		}
		return value, nil
	case "freightctl.refresh_processing_workflow":
		result, err := service.RefreshRun(ctx, scope, args.Run, args.Key)
		if err != nil {
			return nil, err
		}
		var body struct {
			Kind   string            `json:"kind"`
			Status *workflow.RunView `json:"status"`
		}
		if json.Unmarshal(result.Resource, &body) != nil || body.Kind != "workflow_run_refresh" {
			return nil, store.ErrIsolation
		}
		value, err := mcpProcessingStatus(body.Status, "original-command-receipt")
		if err != nil {
			return nil, err
		}
		value["replayed"] = result.Replayed
		return value, nil
	case "freightctl.cancel_processing_workflow":
		var decision workflow.Decision
		if workflow.Decode(args.Request, &decision) != nil {
			return nil, workflow.ErrInput
		}
		result, err := service.Cancel(ctx, scope, args.Run, args.Key, decision)
		if err != nil {
			return nil, err
		}
		var body workflow.RunView
		if json.Unmarshal(result.Resource, &body) != nil {
			return nil, store.ErrIsolation
		}
		value, err := mcpProcessingStatus(&body, "original-command-receipt")
		if err != nil {
			return nil, err
		}
		value["replayed"] = result.Replayed
		return value, nil
	}
	return nil, workflow.ErrInput
}
