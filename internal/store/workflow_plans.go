package store

import (
	"context"
	"encoding/json"
)

// WorkflowRoutingFacts derives metadata from the accepted file and its exact
// original captured input. It accepts no caller-supplied filename or batch.
func (t *Transaction) WorkflowRoutingFacts(ctx context.Context, workflow string, version int, hash, file string) (json.RawMessage, error) {
	var facts []byte
	err := t.Tx.QueryRow(ctx, `SELECT freightctl_program_run_facts($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, workflow, version, hash, file).Scan(&facts)
	if err != nil {
		return nil, err
	}
	if len(facts) == 0 {
		return nil, ErrState
	}
	return facts, nil
}
