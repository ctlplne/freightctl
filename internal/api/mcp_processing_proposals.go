package api

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func mcpProposalSummary(r store.ProcessingProposalSummary) (map[string]any, error) {
	if !store.ValidID(r.ID) || !store.ValidID(r.Author) || !store.ValidID(r.Executor) || r.Author == r.Executor || !mcpUploadDigest.MatchString(r.Hash) || r.Revision < 1 || r.ExpiresAt.IsZero() {
		return nil, store.ErrIsolation
	}
	switch r.State {
	case "pending", "adopted", "rejected", "withdrawn":
	default:
		return nil, store.ErrIsolation
	}
	if (r.State == "pending" && r.Revision != 1) || (r.State != "pending" && r.Revision != 2) || (r.State == "adopted") != (r.Adopted != nil) {
		return nil, store.ErrIsolation
	}
	value := map[string]any{"proposal_id": r.ID, "author_id": r.Author, "executor_id": r.Executor, "definition_hash": r.Hash, "recorded_state": r.State, "revision": r.Revision, "expires_at": r.ExpiresAt}
	if r.Adopted != nil {
		if !store.ValidID(r.Adopted.ID) || r.Adopted.Version < 1 || !mcpUploadDigest.MatchString(r.Adopted.Hash) {
			return nil, store.ErrIsolation
		}
		value["adopted_workflow"] = r.Adopted
	}
	return value, nil
}

func mcpProposalReceipt(r *workflow.Result) (map[string]any, error) {
	var body struct {
		Profile     string                               `json:"profile"`
		Observation string                               `json:"observation"`
		Proposal    store.ProcessingProposalSummary      `json:"proposal"`
		Workflow    *workflow.ProcessingReviewedWorkflow `json:"adopted_workflow,omitempty"`
	}
	if r == nil || workflow.Decode(r.Resource, &body) != nil || body.Profile != workflow.ProcessingProposalProfile || body.Observation != "original-command-receipt" {
		return nil, store.ErrIsolation
	}
	value, err := mcpProposalSummary(body.Proposal)
	if err != nil {
		return nil, err
	}
	if (body.Proposal.Adopted != nil) != (body.Workflow != nil) || body.Workflow != nil && (body.Workflow.ID != body.Proposal.Adopted.ID || body.Workflow.Version != body.Proposal.Adopted.Version || body.Workflow.Hash != body.Proposal.Adopted.Hash || body.Workflow.State != "draft" || body.Workflow.Revision != 1 || body.Workflow.ApprovalAuthority != 0) {
		return nil, store.ErrIsolation
	}
	value["profile"] = workflow.ProcessingProposalProfile
	value["observation"] = body.Observation
	value["current"] = "not-checked"
	value["replayed"] = r.Replayed
	value["approval"] = "not-granted"
	value["execution"] = "not-granted"
	return value, nil
}

func (s *Server) mcpProcessingProposalControl(ctx context.Context, scope store.Scope, name string, args mcpToolArguments) (any, error) {
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	if name == "freightctl.list_processing_proposals" {
		limit := args.Limit
		if limit == 0 {
			limit = 25
		}
		page, err := service.ProcessingProposals(ctx, scope, args.After, limit)
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]any, 0, len(page.Proposals))
		seen := map[string]bool{}
		for _, r := range page.Proposals {
			value, err := mcpProposalSummary(r)
			if err != nil {
				return nil, err
			}
			if seen[r.ID] {
				return nil, store.ErrIsolation
			}
			seen[r.ID] = true
			rows = append(rows, value)
		}
		if len(rows) > 100 || (page.Next != "" && (len(page.Proposals) == 0 || page.Proposals[len(page.Proposals)-1].ID != page.Next)) {
			return nil, store.ErrIsolation
		}
		return map[string]any{"profile": workflow.ProcessingProposalProfile, "proposals": rows, "next": page.Next, "observation": "current-metadata-only", "approval": "not-granted", "execution": "not-granted"}, nil
	}
	if name == "freightctl.inspect_processing_proposal" {
		view, err := service.ProcessingProposal(ctx, scope, args.Proposal)
		if err != nil {
			return nil, err
		}
		r := view.Proposal
		value, err := mcpProposalSummary(store.ProcessingProposalSummary{ID: r.ID, Author: r.Definition.Author.Actor, Executor: r.Definition.Executor.Actor, Hash: r.Hash, State: r.State, Revision: r.Revision, Adopted: r.Adopted, ExpiresAt: r.Definition.ExpiresAt})
		if err != nil {
			return nil, err
		}
		value["profile"] = view.Profile
		value["workflow_definition_hash"] = r.Definition.WorkflowHash
		value["participant_bindings_current_at_observation"] = view.ParticipantsCurrent
		value["expired_at_observation"] = view.Expired
		value["approval"] = "not-granted"
		value["execution"] = "not-granted"
		value["definition_disclosed"] = args.DiscloseDefinition
		if args.DiscloseDefinition {
			value["definition"] = r.Definition.Definition
		}
		return value, nil
	}
	if name == "freightctl.propose_processing_definition" {
		var request workflow.ProcessingProposalRequest
		if workflow.Decode(args.Request, &request) != nil {
			return nil, workflow.ErrInput
		}
		result, err := service.ProposeProcessingWorkflow(ctx, scope, args.Key, request)
		if err != nil {
			return nil, err
		}
		return mcpProposalReceipt(result)
	}
	action := "adopt"
	if name == "freightctl.close_processing_proposal" {
		action = args.Action
		if action != "reject" && action != "withdraw" {
			return nil, workflow.ErrInput
		}
	} else if name != "freightctl.adopt_processing_proposal" {
		return nil, workflow.ErrInput
	}
	var decision workflow.Decision
	if workflow.Decode(args.Request, &decision) != nil {
		return nil, workflow.ErrInput
	}
	result, err := service.DecideProcessingProposal(ctx, scope, args.Proposal, args.Key, action, decision)
	if err != nil {
		return nil, err
	}
	return mcpProposalReceipt(result)
}
