package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ExecutionBinding connects a delivery to the approved configuration and exact
// preceding step receipts. It never selects the latest connection or workflow.
type ExecutionBinding struct {
	WorkflowID        string `json:"workflow_id"`
	WorkflowVersion   int    `json:"workflow_version"`
	WorkflowHash      string `json:"workflow_hash"`
	RunID             string `json:"run_id"`
	StepID            string `json:"step_id"`
	ConnectionID      string `json:"connection_id"`
	ConnectionVersion int    `json:"connection_version"`
	ConnectionHash    string `json:"connection_hash"`
}
type Configuration struct {
	ID                string          `json:"id"`
	Version           int             `json:"version"`
	Definition        json.RawMessage `json:"definition"`
	Hash              string          `json:"definition_hash"`
	State             string          `json:"state"`
	Revision          int64           `json:"revision"`
	ApprovalAuthority int64           `json:"approval_authority"`
}
type WorkflowRun struct {
	ID              string `json:"id"`
	WorkflowID      string `json:"workflow_id"`
	WorkflowVersion int    `json:"workflow_version"`
	WorkflowHash    string `json:"workflow_hash"`
	FileID          string `json:"file_id"`
	Source          File   `json:"source"`
	StorageID       string `json:"storage_id"`
	Root            string `json:"namespace_root"`
	Authority       int64  `json:"authority_revision"`
	State           string `json:"state"`
	Reason          string `json:"reason"`
	Revision        int64  `json:"revision"`
}
type WorkflowStep struct {
	RunID             string `json:"run_id"`
	ID                string `json:"step_id"`
	Ordinal           int    `json:"ordinal"`
	ConnectionID      string `json:"connection_id"`
	ConnectionVersion int    `json:"connection_version"`
	ConnectionHash    string `json:"connection_hash"`
	DeliveryID        string `json:"delivery_id"`
}

func configurationTable(connection bool) (string, string, string) {
	if connection {
		return "connection_revisions", "connection_id", "ConnectionRevisionChanged"
	}
	return "workflow_revisions", "workflow_id", "WorkflowRevisionChanged"
}
func (t *Transaction) Configuration(ctx context.Context, connection bool, id string, version int, lock bool) (*Configuration, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	table, column, _ := configurationTable(connection)
	authority := "approval_authority"
	if connection {
		authority = "0::bigint"
	}
	q := `SELECT ` + column + `::text,version,definition,definition_hash,state,revision,` + authority + ` FROM ` + table + ` WHERE ` + column + `=$1 AND version=$2 AND actor_id=$3`
	if lock {
		q += ` FOR UPDATE`
	}
	c := &Configuration{}
	err := t.Tx.QueryRow(ctx, q, id, version, t.Actor).Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision, &c.ApprovalAuthority)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}
func (t *Transaction) ConfigurationVersion(ctx context.Context, connection bool, id string) (int, error) {
	table, column, _ := configurationTable(connection)
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":"+table+":"+id); err != nil {
		return 0, err
	}
	var version int
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM `+table+` WHERE `+column+`=$1 AND actor_id=$2`, id, t.Actor).Scan(&version)
	return version, err
}
func (t *Transaction) SaveConfiguration(ctx context.Context, connection bool, c *Configuration, previous int64) error {
	table, column, kind := configurationTable(connection)
	event, err := t.Append(ctx, kind, c.ID, c)
	if err != nil {
		return err
	}
	if previous == 0 {
		columns := `tenant_id,partner_id,actor_id,` + column + `,version,definition,definition_hash,state,revision,changed_event_id`
		values := `$1,$2,$3,$4,$5,$6,$7,$8,$9,$10`
		args := []any{t.Scope.Tenant, t.Scope.Partner, t.Actor, c.ID, c.Version, c.Definition, c.Hash, c.State, c.Revision, event}
		if !connection {
			columns += `,approval_authority`
			values += `,$11`
			args = append(args, c.ApprovalAuthority)
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO `+table+`(`+columns+`) VALUES(`+values+`)`, args...)
		return err
	}
	args := []any{c.State, c.Revision, event, c.ID, c.Version, t.Actor, previous}
	extra := ""
	if !connection {
		extra = `,approval_authority=$8`
		args = append(args, c.ApprovalAuthority)
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE `+table+` SET state=$1,revision=$2,changed_event_id=$3`+extra+` WHERE `+column+`=$4 AND version=$5 AND actor_id=$6 AND revision=$7`, args...)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) WorkflowRun(ctx context.Context, id string, lock bool) (*WorkflowRun, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	q := `SELECT run_id::text,workflow_id::text,workflow_version,workflow_hash,file_id::text,source,storage_id::text,namespace_root,authority_revision,state,reason,revision FROM workflow_runs WHERE run_id=$1 AND actor_id=$2`
	if lock {
		q += ` FOR UPDATE`
	}
	r := &WorkflowRun{}
	var source []byte
	err := t.Tx.QueryRow(ctx, q, id, t.Actor).Scan(&r.ID, &r.WorkflowID, &r.WorkflowVersion, &r.WorkflowHash, &r.FileID, &source, &r.StorageID, &r.Root, &r.Authority, &r.State, &r.Reason, &r.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(source, &r.Source)
	return r, err
}
func (t *Transaction) SaveWorkflowRun(ctx context.Context, r *WorkflowRun, previous int64) error {
	event, err := t.Append(ctx, "WorkflowRunChanged", r.ID, r)
	if err != nil {
		return err
	}
	if previous == 0 {
		source, err := json.Marshal(r.Source)
		if err != nil {
			return err
		}
		_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_runs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, r.ID, r.WorkflowID, r.WorkflowVersion, r.WorkflowHash, r.FileID, source, r.StorageID, r.Root, r.Authority, r.State, r.Reason, r.Revision, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE workflow_runs SET state=$1,reason=$2,revision=$3,changed_event_id=$4 WHERE run_id=$5 AND actor_id=$6 AND revision=$7`, r.State, r.Reason, r.Revision, event, r.ID, t.Actor, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) BindWorkflowStep(ctx context.Context, s *WorkflowStep) error {
	event, err := t.Append(ctx, "WorkflowStepBound", s.RunID, s)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_steps VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, s.RunID, s.ID, s.Ordinal, s.ConnectionID, s.ConnectionVersion, s.ConnectionHash, s.DeliveryID, event)
	return err
}
func (t *Transaction) WorkflowSteps(ctx context.Context, id string) ([]WorkflowStep, error) {
	rows, err := t.Tx.Query(ctx, `SELECT run_id::text,step_id,ordinal,connection_id::text,connection_version,connection_hash,delivery_id::text FROM workflow_steps WHERE run_id=$1 AND actor_id=$2 ORDER BY ordinal LIMIT 17`, id, t.Actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []WorkflowStep{}
	for rows.Next() {
		var s WorkflowStep
		if err = rows.Scan(&s.RunID, &s.ID, &s.Ordinal, &s.ConnectionID, &s.ConnectionVersion, &s.ConnectionHash, &s.DeliveryID); err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	if len(result) > 16 {
		return nil, ErrLimit
	}
	return result, rows.Err()
}
func (t *Transaction) CheckExecutionBinding(ctx context.Context, b *ExecutionBinding) error {
	return t.checkExecutionBinding(ctx, b, false)
}

// CheckExecutionObservationBinding retains ordinary authority/source/workflow
// checks while permitting read-only receipt observation after a schedule cutoff.
// It grants no lease, stream write, retry or new effect.
func (t *Transaction) CheckExecutionObservationBinding(ctx context.Context, b *ExecutionBinding) error {
	return t.checkExecutionBinding(ctx, b, true)
}
func (t *Transaction) checkExecutionBinding(ctx context.Context, b *ExecutionBinding, observation bool) error {
	if b == nil {
		return nil
	}
	if err := t.Require("workflow_execute"); err != nil {
		return err
	}
	var allowed bool
	err := t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM workflow_steps s JOIN workflow_runs r USING(tenant_id,partner_id,run_id)
 JOIN workflow_revisions w ON (w.tenant_id,w.partner_id,w.workflow_id,w.version)=(r.tenant_id,r.partner_id,r.workflow_id,r.workflow_version)
 JOIN connection_revisions c ON (c.tenant_id,c.partner_id,c.connection_id,c.version)=(s.tenant_id,s.partner_id,s.connection_id,s.connection_version)
 WHERE s.run_id=$1 AND s.step_id=$2 AND s.actor_id=$3 AND r.workflow_id=$4 AND r.workflow_version=$5 AND r.workflow_hash=$6 AND s.connection_id=$7 AND s.connection_version=$8 AND s.connection_hash=$9
 AND r.state IN ('queued','running','attention') AND r.authority_revision=$10 AND r.namespace_root=$11
 AND w.state='approved' AND w.definition_hash=r.workflow_hash AND w.approval_authority=r.authority_revision AND c.state='active' AND c.definition_hash=s.connection_hash
	 AND NOT EXISTS(SELECT 1 FROM workflow_steps planned JOIN connection_revisions configured ON (configured.tenant_id,configured.partner_id,configured.connection_id,configured.version)=(planned.tenant_id,planned.partner_id,planned.connection_id,planned.connection_version) WHERE (planned.tenant_id,planned.partner_id,planned.run_id)=(s.tenant_id,s.partner_id,s.run_id) AND (configured.state<>'active' OR configured.definition_hash<>planned.connection_hash))
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(w.definition->'steps') planned(value) LEFT JOIN pgp_keys k ON (k.tenant_id,k.partner_id,k.key_id,k.version)=(w.tenant_id,w.partner_id,(planned.value->'encryption'->'key'->>'id')::uuid,(planned.value->'encryption'->'key'->>'version')::integer) WHERE planned.value ? 'encryption' AND (k.key_id IS NULL OR k.state<>'active' OR k.definition_hash IS DISTINCT FROM planned.value->'encryption'->'key'->>'hash' OR k.definition->>'purpose' IS DISTINCT FROM 'encrypt' OR (k.valid_until IS NOT NULL AND k.valid_until<=clock_timestamp()) OR NOT (k.definition->'recipient'->'profiles' ? (planned.value->'encryption'->>'profile'))))
 AND NOT EXISTS(SELECT 1 FROM workflow_steps prior JOIN delivery_intents d USING(tenant_id,partner_id,delivery_id) WHERE (prior.tenant_id,prior.partner_id,prior.run_id)=(s.tenant_id,s.partner_id,s.run_id) AND prior.ordinal<s.ordinal AND d.state<>'succeeded') AND freightctl_onboarding_run_current($12,$13,$3,s.run_id,$10,$11))`, b.RunID, b.StepID, t.Actor, b.WorkflowID, b.WorkflowVersion, b.WorkflowHash, b.ConnectionID, b.ConnectionVersion, b.ConnectionHash, t.AuthorityRevision, t.Root, t.Scope.Tenant, t.Scope.Partner).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrState
	}
	if !observation {
		if err := t.CheckScheduleBinding(ctx, b.RunID); err != nil {
			return err
		}
	}
	return t.checkOnboardingProofAvailability(ctx, b.RunID)
}
func (t *Transaction) WorkflowReplay(ctx context.Context, key, meaning string) (json.RawMessage, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":workflow-receipt:"+key); err != nil {
		return nil, err
	}
	var hash string
	var result json.RawMessage
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM workflow_receipts WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&hash, &result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if hash != meaning {
		return nil, ErrConflict
	}
	return result, nil
}
func (t *Transaction) WorkflowReceipt(ctx context.Context, key, meaning, id string, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	event, err := t.Append(ctx, "WorkflowCommandCompleted", id, map[string]any{"request_key": key, "request_hash": meaning, "result": json.RawMessage(data)})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, id, data, event)
	return err
}
func (t *Transaction) DeliveryAdmission(ctx context.Context, needed int) error {
	if needed < 1 || needed > 128 {
		return ErrLimit
	}
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":delivery-admission"); err != nil {
		return err
	}
	var count int
	if err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM delivery_intents WHERE actor_id=$1 AND state NOT IN ('succeeded','blocked','cancelled')`, t.Actor).Scan(&count); err != nil {
		return err
	}
	if count+needed > 128 {
		return ErrLimit
	}
	return nil
}
