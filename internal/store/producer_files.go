package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

func (t *Transaction) ConfigureProducerFile(ctx context.Context, f *File, ref OnboardingReference) error {
	p, err := t.ProcessingPolicy(ctx, ref)
	if err != nil {
		return err
	}
	if p.State != "output_active" {
		return ErrRevision
	}
	return t.configurePolicyFile(ctx, f, p)
}

// A released output may remain governed by its own contract while ingress keeps
// another format. This is a dependency check, never sender/recipient authority.
func (t *Transaction) exchangeFilePolicyCurrent(ctx context.Context, f *File, defaultPolicy *Configuration) error {
	if err := exchangePolicyCurrent(f, defaultPolicy); err == nil {
		return nil
	}
	var state string
	err := t.Tx.QueryRow(ctx, `SELECT s.state FROM processing_output_status s JOIN file_releases r ON (r.tenant_id,r.partner_id,r.policy_id,r.policy_version,r.policy_hash)=(s.tenant_id,s.partner_id,s.policy_id,s.policy_version,s.policy_hash) WHERE r.file_id=$1 FOR SHARE OF s`, f.ID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrState
	}
	if err != nil {
		return err
	}
	if state != "output_active" {
		return ErrState
	}
	var available bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_released_output_available($1,$2,$3)`, t.Scope.Tenant, t.Scope.Partner, f.ID).Scan(&available); err != nil {
		return err
	}
	if !available {
		return ErrState
	}
	return nil
}

func (t *Transaction) BindProducerFile(ctx context.Context, f *File, storageID string, target *PathCommand, ref OnboardingReference) (bool, error) {
	p, err := t.ProcessingPolicy(ctx, ref)
	if err != nil {
		return false, err
	}
	expected, formatErr := IntakeFilePolicy(p)
	if p.State != "output_active" || formatErr != nil || f.Policy != expected || !ValidID(storageID) {
		return false, ErrState
	}
	return t.bindPolicyFile(ctx, f, storageID, target, p)
}

// Only immutable generated acceptance schema6 can select an output-only policy
// for ordinary checking. Caller-controlled file policy strings cannot do so.
func (t *Transaction) FileCheckPolicy(ctx context.Context, c *FileCheck) (*Configuration, error) {
	if c == nil || !ValidID(c.FileID) {
		return nil, ErrState
	}
	var schema string
	var raw []byte
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(e.payload->>'schema_version',''),r.definition->'plan'->'context'->'policy' FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id,e.resource_id,e.kind)=(f.tenant_id,f.partner_id,f.accepted_event_id,f.file_id,'FileAccepted') LEFT JOIN record_projections r ON (r.tenant_id,r.partner_id,r.actor_id,r.new_file_id,r.state)=(f.tenant_id,f.partner_id,e.actor_id,f.file_id,'completed') AND r.actor_id=$2 AND r.projection_id::text=e.payload->'record_projection'->>'id' AND r.definition_hash=e.payload->'record_projection'->>'definition_hash' AND r.definition->>'schema_version'='3' AND r.definition->'plan'->>'profile'='producer-record-projection-v1' WHERE f.file_id=$1`, c.FileID, t.Actor).Scan(&schema, &raw)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if schema != "6" {
		return t.IntakePolicy(ctx, false)
	}
	var ref OnboardingReference
	if len(raw) == 0 || json.Unmarshal(raw, &ref) != nil || ref.ID != c.PolicyID || ref.Version != c.PolicyVersion || ref.Hash != c.PolicyHash {
		return nil, ErrIsolation
	}
	p, err := t.ProcessingPolicy(ctx, ref)
	if err == nil && p.State != "output_active" {
		return nil, ErrRevision
	}
	return p, err
}
