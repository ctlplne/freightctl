package api

import (
	"context"
	"encoding/json"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func projectionReviewHash(plan checks.ProjectionPlan) (string, error) {
	wire, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return secure.Digest(wire), nil
}

// Keep host/operator review bindings out of model context. Hashes pin the full
// server plan;metadata here confers neither approval nor access to held bytes.
func mcpProjectionPreview(v *checks.ProjectionPreview) (map[string]any, error) {
	if v == nil || v.Plan.Schema != 2 || v.Plan.Profile != checks.ScopedProjectionProfile {
		return nil, store.ErrIsolation
	}
	hash, err := projectionReviewHash(v.Plan)
	if err != nil {
		return nil, err
	}
	rules, err := json.Marshal(v.Plan.Projection)
	if err != nil {
		return nil, err
	}
	f := v.Plan.Context.Source.File
	return map[string]any{"profile": checks.ScopedProjectionProfile, "review_hash": hash, "source": store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}, "source_policy": v.Plan.SourcePolicy, "output_policy": v.Plan.Context.Policy, "mapping_hash": secure.Digest(rules), "output_contract_hash": v.Plan.OutputContractHash, "authority_revision": v.Plan.Context.Authority, "namespace_root_digest": secure.Digest([]byte(v.Plan.Context.Root)), "source_proof_valid_until": v.Plan.ProofValidUntil, "effects": "new-held-artifact-after-separate-approval", "durable_effects": "none", "external_contact": false, "release_required": true}, nil
}
func mcpProjectionFacts(r *store.RecordProjection, replayed, current bool, observation string) (map[string]any, error) {
	return mcpProjectionProfileFacts(r, replayed, current, observation, "")
}
func mcpProjectionProfileFacts(r *store.RecordProjection, replayed, current bool, observation, run string) (map[string]any, error) {
	if r == nil || !store.ValidID(r.ID) || !mcpUploadDigest.MatchString(r.Hash) {
		return nil, store.ErrIsolation
	}
	d, err := checks.DecodeProjectionDefinition(r)
	if err != nil {
		return nil, store.ErrIsolation
	}
	// Direct projection tools remain scoped-only. Producer/composed attempts
	// may be described only for their exact separately governed workflow run.
	profile := d.Schema == 1 && d.Plan.Schema == 2 && d.Plan.Profile == checks.ScopedProjectionProfile && d.Workflow == nil && run == ""
	if run != "" {
		profile = d.Workflow != nil && d.Workflow.RunID == run && (d.Schema == 2 && d.Plan.Profile == checks.ScopedProjectionProfile ||
			d.Schema == 3 && d.Plan.Profile == checks.ProducerProjectionProfile ||
			d.Schema == 4 && d.Plan.Profile == checks.ComposedProducerProjectionProfile)
	}
	if !profile {
		return nil, store.ErrForbidden
	}
	result := map[string]any{"profile": d.Plan.Profile, "projection_id": r.ID, "definition_hash": r.Hash, "state": r.State, "revision": r.Revision, "attempts": r.Attempts, "observation": observation, "current": current, "replayed": replayed, "external_contact": false, "release_inherited": false}
	if observation == "original-command-receipt" {
		result["current"] = "not-checked"
	}
	if r.State == "running" {
		result["attempt"] = checks.ProjectionAttempt{ID: r.ID, Number: r.Attempts, WorkerID: r.WorkerID}
		result["lease_until"] = r.LeaseUntil
	}
	if r.State == "completed" {
		var output checks.ProjectionOutput
		if json.Unmarshal(r.Result, &output) != nil || output.Kind != "record_projection_output" || output.File.ID != r.FileID || !store.ValidID(output.File.ID) || output.File.Size < 0 || !mcpUploadDigest.MatchString(output.File.SHA256) || !store.ValidArtifactPolicy(output.File.Policy) || output.Acceptance != "durable-held-pending-checks-and-release" {
			return nil, store.ErrIsolation
		}
		f := output.File
		result["artifact"] = store.ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}
		result["acceptance"] = output.Acceptance
	}
	if r.State == "failed" {
		var failure struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(r.Result, &failure) != nil {
			return nil, store.ErrIsolation
		}
		switch failure.Code {
		case "processing_unavailable", "processing_cancelled", "processing_deadline", "review_stale", "integrity_mismatch", "capacity_unavailable":
			result["code"] = failure.Code
		default:
			return nil, store.ErrIsolation
		}
	}
	return result, nil
}
func mcpProjectionReceipt(r *checks.Result) (map[string]any, error) {
	if r == nil {
		return nil, store.ErrIsolation
	}
	var v struct {
		Kind       string                  `json:"kind"`
		Projection *store.RecordProjection `json:"projection"`
	}
	if json.Unmarshal(r.Resource, &v) != nil || v.Kind != "record_projection" {
		return nil, store.ErrIsolation
	}
	return mcpProjectionFacts(v.Projection, r.Replayed, false, "original-command-receipt")
}
func (s *Server) mcpProjectionControl(ctx context.Context, scope store.Scope, name string, args mcpToolArguments) (any, error) {
	if name == "freightctl.preview_record_projection" || name == "freightctl.propose_record_projection" {
		var options checks.ProjectionOptions
		if workflow.Decode(args.Request, &options) != nil || options.Profile != checks.ScopedProjectionProfile {
			return nil, store.ErrExchangeInput
		}
		if name == "freightctl.propose_record_projection" {
			result, err := s.Checks.ProposeReviewedProjection(ctx, scope, args.Key, args.File, args.ReviewHash, options)
			if err != nil {
				return nil, err
			}
			return mcpProjectionReceipt(result)
		}
		preview, err := s.Checks.PreviewProjection(ctx, scope, args.File, options)
		if err != nil {
			return nil, err
		}
		return mcpProjectionPreview(preview)
	}
	// Profile-check even receipt replay. These tools cannot reinterpret legacy
	// root-administrator jobs as scoped processing authority.
	v, err := s.Checks.GetProjection(ctx, scope, args.Projection)
	if err != nil {
		return nil, err
	}
	if _, err = mcpProjectionFacts(v.Projection, false, v.Current, "current-observation"); err != nil {
		return nil, err
	}
	switch name {
	case "freightctl.inspect_record_projection":
		return mcpProjectionFacts(v.Projection, false, v.Current, "current-observation")
	case "freightctl.start_record_projection":
		var request checks.ProjectionStartDecision
		if workflow.Decode(args.Request, &request) != nil {
			return nil, store.ErrExchangeInput
		}
		result, err := s.Checks.StartProjection(ctx, scope, args.Projection, args.Key, request)
		if err != nil {
			return nil, err
		}
		return mcpProjectionReceipt(result)
	case "freightctl.work_record_projection":
		var request checks.ProjectionAttempt
		if workflow.Decode(args.Request, &request) != nil || request.ID != args.Projection {
			return nil, store.ErrExchangeInput
		}
		result, err := s.Checks.WorkProjection(ctx, scope, args.Key, request)
		if err != nil {
			return nil, err
		}
		return mcpProjectionReceipt(result)
	}
	return nil, store.ErrExchangeInput
}
