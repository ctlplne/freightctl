package store

import "context"

// CollectionReplacement is a read model, never a rewritten input assignment or
// permission to send. All fields are taken from one committed SQL snapshot.
type CollectionReplacement struct {
	InputID       string `json:"input_id"`
	JobID         string `json:"job_id"`
	OriginalRunID string `json:"original_run_id"`
	CurrentRunID  string `json:"current_run_id"`
	HandoffID     string `json:"handoff_id"`
	SourceRunID   string `json:"source_run_id"`
}

func (t *Transaction) CollectionReplacements(ctx context.Context, inputs []CollectionInput) ([]CollectionReplacement, error) {
	if len(inputs) > 64 {
		return nil, ErrLimit
	}
	if len(inputs) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(inputs))
	byID := make(map[string]CollectionInput, len(inputs))
	for _, input := range inputs {
		if !ValidID(input.ID) {
			return nil, ErrState
		}
		ids = append(ids, input.ID)
		byID[input.ID] = input
	}
	rows, err := t.Tx.Query(ctx, `SELECT h.input_id::text,h.job_id::text,i.run_id::text,h.planned_run_id::text,h.id::text,h.source_run_id::text
 FROM workflow_collection_handoffs h JOIN workflow_collection_inputs i ON
 (i.tenant_id,i.partner_id,i.actor_id,i.id,i.first_job_id)=(h.tenant_id,h.partner_id,h.actor_id,h.input_id,h.job_id)
 WHERE (h.tenant_id,h.partner_id,h.actor_id)=($1,$2,$3) AND h.input_id=ANY($4::uuid[]) AND h.state='completed'
 AND NOT EXISTS(SELECT 1 FROM workflow_collection_handoffs n WHERE
 (n.tenant_id,n.partner_id,n.actor_id,n.input_id,n.source_run_id,n.state)=(h.tenant_id,h.partner_id,h.actor_id,h.input_id,h.planned_run_id,'completed'))
 ORDER BY h.input_id LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, ids, len(inputs)+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var replacements []CollectionReplacement
	seen := make(map[string]bool, len(inputs))
	for rows.Next() {
		var r CollectionReplacement
		if err := rows.Scan(&r.InputID, &r.JobID, &r.OriginalRunID, &r.CurrentRunID, &r.HandoffID, &r.SourceRunID); err != nil {
			return nil, err
		}
		input, ok := byID[r.InputID]
		if !ok || seen[r.InputID] || input.RunID == nil || r.OriginalRunID != *input.RunID || r.JobID != input.JobID || r.CurrentRunID == r.OriginalRunID || r.CurrentRunID == r.SourceRunID {
			return nil, ErrState
		}
		seen[r.InputID] = true
		replacements = append(replacements, r)
	}
	return replacements, rows.Err()
}
