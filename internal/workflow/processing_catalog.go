package workflow

import (
	"context"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type ProcessingCatalogEntry struct {
	Reference
	Name                string    `json:"name"`
	State               string    `json:"state"`
	Revision            int64     `json:"revision"`
	Kind                string    `json:"kind"`
	SourcePolicyHash    string    `json:"source_policy_hash"`
	OutputKind          string    `json:"output_kind"`
	ColumnCount         int       `json:"column_count"`
	OutputPolicy        Reference `json:"output_policy"`
	ApprovalCurrent     bool      `json:"approval_current"`
	OutputPolicyCurrent bool      `json:"output_policy_current"`
}
type ProcessingCatalog struct {
	Profile    string                   `json:"profile"`
	Authority  int64                    `json:"authority_revision"`
	RootDigest string                   `json:"namespace_root_digest"`
	Workflows  []ProcessingCatalogEntry `json:"workflows"`
	Next       string                   `json:"next,omitempty"`
}

func processingCatalogEntry(c, policy *store.Configuration, authority int64, reviewCurrent bool) (ProcessingCatalogEntry, error) {
	var d Definition
	empty := ProcessingCatalogEntry{}
	if c == nil || !store.ValidID(c.ID) || c.Version < 1 || c.Revision < 1 || authority < 1 || Decode(c.Definition, &d) != nil {
		return empty, store.ErrState
	}
	if c.State != "draft" && c.State != "approved" && c.State != "revoked" {
		return empty, store.ErrState
	}
	if (c.State == "draft") != (c.ApprovalAuthority == 0) {
		return empty, store.ErrState
	}
	d, err := Normalize(d)
	if err != nil || d.Schema != 3 || d.Processing == nil {
		return empty, store.ErrState
	}
	_, hash, err := digest(d)
	if err != nil || hash != c.Hash {
		return empty, store.ErrState
	}
	task := d.Processing
	currentPolicy := policy != nil && policy.State == "active" && task.OutputPolicy == (Reference{ID: policy.ID, Version: policy.Version, Hash: policy.Hash})
	return ProcessingCatalogEntry{Reference: Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}, Name: d.Name, State: c.State, Revision: c.Revision, Kind: task.Kind, SourcePolicyHash: task.Definition.SourcePolicyHash, OutputKind: task.Definition.OutputKind, ColumnCount: len(task.Definition.Columns), OutputPolicy: task.OutputPolicy, ApprovalCurrent: c.State == "approved" && c.ApprovalAuthority == authority && reviewCurrent, OutputPolicyCurrent: currentPolicy}, nil
}

// ProcessingWorkflows is discovery, never an execution-readiness assertion. The
// exact input, permissions, policy and durable effects still need ordinary review.
func (s *Service) ProcessingWorkflows(ctx context.Context, scope store.Scope, after string, limit int) (*ProcessingCatalog, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.beginWorkflow(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		return nil, store.ErrForbidden
	}
	// Take the latest revision of each family before testing the profile. A newer
	// legacy definition must not make an older processing version look current.
	rows, err := t.Tx.Query(ctx, `SELECT w.workflow_id::text,w.version,w.definition,w.definition_hash,w.state,w.revision,w.approval_authority FROM workflow_revisions w WHERE w.actor_id=$1 AND w.definition->>'schema_version'='3' AND ($2='' OR w.workflow_id>nullif($2,'')::uuid) AND w.version=(SELECT max(v.version) FROM workflow_revisions v WHERE (v.tenant_id,v.partner_id,v.actor_id,v.workflow_id)=(w.tenant_id,w.partner_id,$1,w.workflow_id)) ORDER BY w.workflow_id LIMIT $3`, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	candidates := make([]*store.Configuration, 0, limit+1)
	for rows.Next() {
		c := &store.Configuration{}
		if err = rows.Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision, &c.ApprovalAuthority); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	out := &ProcessingCatalog{Profile: "processing-workflow-catalog-v1", Authority: t.AuthorityRevision, RootDigest: secure.Digest([]byte(t.Root)), Workflows: []ProcessingCatalogEntry{}}
	if len(candidates) > limit {
		out.Next = candidates[limit-1].ID
		candidates = candidates[:limit]
	}
	policy, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	for _, c := range candidates {
		reviewCurrent := false
		if c.State == "approved" {
			err = t.CheckProcessingReview(ctx, c.ID, c.Version, c.Hash)
			if err != nil && !errors.Is(err, store.ErrRevision) {
				return nil, err
			}
			reviewCurrent = err == nil
		}
		entry, err := processingCatalogEntry(c, policy, t.AuthorityRevision, reviewCurrent)
		if err != nil {
			return nil, err
		}
		out.Workflows = append(out.Workflows, entry)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return out, t.Tx.Commit(ctx)
}
