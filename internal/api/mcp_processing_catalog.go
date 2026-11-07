package api

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func mcpProcessingCatalog(page *workflow.ProcessingCatalog) (map[string]any, error) {
	if page == nil || page.Profile != "processing-workflow-catalog-v1" || page.Authority < 1 || !mcpUploadDigest.MatchString(page.RootDigest) || len(page.Workflows) > 100 || (page.Next != "" && !store.ValidID(page.Next)) {
		return nil, store.ErrIsolation
	}
	rows := make([]map[string]any, 0, len(page.Workflows))
	seen := map[string]bool{}
	for _, r := range page.Workflows {
		if !store.ValidID(r.ID) || r.Version < 1 || !mcpUploadDigest.MatchString(r.Hash) || r.Revision < 1 || r.Kind != "records.project" || !mcpUploadDigest.MatchString(r.SourcePolicyHash) || !store.ValidID(r.OutputPolicy.ID) || r.OutputPolicy.Version < 1 || !mcpUploadDigest.MatchString(r.OutputPolicy.Hash) || r.ColumnCount < 1 || r.ColumnCount > 128 || (r.OutputKind != "csv" && r.OutputKind != "json_records") || (r.State != "draft" && r.State != "approved" && r.State != "revoked") || (r.ApprovalCurrent && r.State != "approved") || seen[r.ID] {
			return nil, store.ErrIsolation
		}
		seen[r.ID] = true
		rows = append(rows, map[string]any{"workflow": r.Reference, "state": r.State, "revision": r.Revision, "kind": r.Kind, "source_policy_hash": r.SourcePolicyHash, "output_kind": r.OutputKind, "column_count": r.ColumnCount, "output_policy": r.OutputPolicy, "approval_current": r.ApprovalCurrent, "output_policy_current": r.OutputPolicyCurrent})
	}
	if page.Next != "" && (len(page.Workflows) == 0 || page.Workflows[len(page.Workflows)-1].ID != page.Next) {
		return nil, store.ErrIsolation
	}
	return map[string]any{"profile": page.Profile, "authority_revision": page.Authority, "namespace_root_digest": page.RootDigest, "workflows": rows, "next": page.Next, "observation": "current-metadata-only", "execution_readiness": "not-checked", "effects": "none"}, nil
}
func (s *Server) mcpListProcessingWorkflows(ctx context.Context, scope store.Scope, args mcpToolArguments) (any, error) {
	limit := args.Limit
	if limit == 0 {
		limit = 25
	}
	service := &workflow.Service{Custody: s.Service, Processor: s.Checks}
	page, err := service.ProcessingWorkflows(ctx, scope, args.After, limit)
	if err != nil {
		return nil, err
	}
	return mcpProcessingCatalog(page)
}
