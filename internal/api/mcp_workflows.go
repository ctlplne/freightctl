package api

import (
	"context"
	"encoding/json"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func mcpWorkflowReview(p *workflow.Preview) (map[string]any, error) {
	if p == nil || p.ExternalContact || !p.ApprovalRequired {
		return nil, store.ErrIsolation
	}
	raw, err := json.Marshal(p.Definition)
	if err != nil || secure.Digest(raw) != p.Hash {
		return nil, store.ErrIsolation
	}
	result := map[string]any{"profile": "ordinary-workflow-review-v1", "state": "definition-validated-only", "definition_hash": p.Hash, "schema_version": p.Definition.Schema, "step_count": len(p.Definition.Steps), "effect_count": len(p.Effects), "has_collection_source": p.Collection != nil, "approval_required": true, "external_contact": false, "durable_effects": "none", "storage_verification": "not-checked"}
	if task := p.Definition.Processing; task != nil {
		rules, e := json.Marshal(task.Definition)
		if e != nil {
			return nil, e
		}
		result["processing"] = map[string]any{"kind": task.Kind, "mapping_hash": secure.Digest(rules), "output_kind": task.Definition.OutputKind, "column_count": len(task.Definition.Columns), "output_policy": task.OutputPolicy, "release_required": true, "delivery_intents": 0}
	}
	if p.Source != nil {
		if !store.ValidID(p.Source.ID) || p.Source.Size < 0 || !mcpUploadDigest.MatchString(p.Source.SHA256) {
			return nil, store.ErrIsolation
		}
		result["source"] = store.ExchangeArtifact{ID: p.Source.ID, Size: p.Source.Size, SHA256: p.Source.SHA256, Policy: p.Source.Policy}
	}
	return result, nil
}
func mcpWorkflowProposal(r *workflow.Result) (map[string]any, error) {
	if r == nil {
		return nil, store.ErrIsolation
	}
	var c store.Configuration
	if json.Unmarshal(r.Resource, &c) != nil || !store.ValidID(c.ID) || c.Version < 1 || c.Revision != 1 || c.State != "draft" || !mcpUploadDigest.MatchString(c.Hash) {
		return nil, store.ErrIsolation
	}
	var definition workflow.Definition
	if workflow.Decode(c.Definition, &definition) != nil {
		return nil, store.ErrIsolation
	}
	normalized, err := workflow.Normalize(definition)
	if err != nil {
		return nil, store.ErrIsolation
	}
	canonical, err := json.Marshal(normalized)
	if err != nil || secure.Digest(canonical) != c.Hash {
		return nil, store.ErrIsolation
	}
	return map[string]any{"profile": "ordinary-workflow-draft-v1", "workflow_id": c.ID, "version": c.Version, "definition_hash": c.Hash, "revision": c.Revision, "accepted_state": c.State, "observation": "original-command-receipt", "current_state": "not-checked", "approval_required": true, "external_contact": false, "replayed": r.Replayed}, nil
}

func (s *Server) mcpWorkflowControl(ctx context.Context, scope store.Scope, name string, args mcpToolArguments) (any, error) {
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	switch name {
	case "freightctl.validate_workflow":
		var request workflow.PreviewRequest
		if workflow.Decode(args.Request, &request) != nil {
			return nil, workflow.ErrInput
		}
		preview, err := service.Validate(ctx, scope, request)
		if err != nil {
			return nil, err
		}
		return mcpWorkflowReview(preview)
	case "freightctl.propose_workflow":
		var request workflow.DraftRequest
		if workflow.Decode(args.Request, &request) != nil {
			return nil, workflow.ErrInput
		}
		result, err := service.Draft(ctx, scope, args.Key, request)
		if err != nil {
			return nil, err
		}
		return mcpWorkflowProposal(result)
	default:
		return nil, workflow.ErrInput
	}
}
