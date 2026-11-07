package store

import (
	"context"
	"encoding/json"
	"errors"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// ProducedSource identifies a completed, owned producer output. It is lineage,
// not an approval, release, forwarding permission or execution credential.
type ProducedSource struct {
	Profile        string                  `json:"profile"`
	File           File                    `json:"file"`
	ProjectionID   string                  `json:"projection_id"`
	ProjectionHash string                  `json:"projection_hash"`
	Producer       ProcessingOutputBinding `json:"producer_binding"`
}

func (s *ProducedSource) Validate(f *File, c *Configuration, actor ExchangeParticipant) error {
	if s == nil {
		return ErrIsolation
	}
	expected, err := producedSource(f, c, &s.Producer, actor, s.ProjectionID, s.ProjectionHash)
	if err != nil {
		return err
	}
	if *s != *expected {
		return ErrIsolation
	}
	return nil
}

func producedSource(f *File, c *Configuration, b *ProcessingOutputBinding, actor ExchangeParticipant, projection, hash string) (*ProducedSource, error) {
	if f == nil || !ValidID(f.ID) || !ValidID(f.EventID) || f.Size < 0 || !browserSecretHash.MatchString(f.SHA256) || !ValidID(projection) || !browserSecretHash.MatchString(hash) {
		return nil, ErrIsolation
	}
	if err := processingOutputSelection(c, b, actor); err != nil {
		return nil, err
	}
	policy, err := IntakeFilePolicy(c)
	if err != nil || f.Policy != policy {
		return nil, ErrIsolation
	}
	return &ProducedSource{Profile: "owned-produced-source-v1", File: *f, ProjectionID: projection, ProjectionHash: hash, Producer: *b}, nil
}

// ProducedSource resolves trusted immutable acceptance and completed intent
// rows. Callers cannot manufacture lineage from a policy string or a receipt.
// The family lock also serializes current-contract revocation with consumption.
func (t *Transaction) ProducedSource(ctx context.Context, f *File) (*ProducedSource, error) {
	if f == nil || !ValidID(f.ID) || !ValidID(f.EventID) {
		return nil, ErrNotFound
	}
	var projection, hash, policyID, policyHash string
	var version int
	err := t.Tx.QueryRow(ctx, `SELECT r.projection_id::text,r.definition_hash,r.definition->'plan'->'context'->'policy'->>'id',(r.definition->'plan'->'context'->'policy'->>'version')::integer,r.definition->'plan'->'context'->'policy'->>'hash'
FROM files x JOIN events e ON (e.tenant_id,e.partner_id,e.event_id,e.resource_id,e.kind)=(x.tenant_id,x.partner_id,x.accepted_event_id,x.file_id,'FileAccepted')
JOIN record_projection_slots s ON (s.tenant_id,s.partner_id,s.actor_id,s.file_id)=(x.tenant_id,x.partner_id,e.actor_id,x.file_id)
JOIN record_projections r ON (r.tenant_id,r.partner_id,r.actor_id,r.projection_id,r.new_file_id,r.state)=(s.tenant_id,s.partner_id,s.actor_id,s.projection_id,x.file_id,'completed')
WHERE (x.tenant_id,x.partner_id,x.file_id,x.accepted_event_id,x.size_bytes,x.sha256,x.policy,e.actor_id)=($1,$2,$3,$4,$5,$6,$7,$8)
AND e.payload->>'size_bytes'=x.size_bytes::text AND e.payload->>'sha256'=x.sha256 AND e.payload->>'policy'=x.policy
AND e.payload->'record_projection'->>'id'=r.projection_id::text AND e.payload->'record_projection'->>'definition_hash'=r.definition_hash
AND ((e.payload->>'schema_version'='6' AND r.definition->>'schema_version'='3' AND r.definition->'plan'->>'profile'='producer-record-projection-v1')
OR (e.payload->>'schema_version'='7' AND r.definition->>'schema_version'='4' AND r.definition->'plan'->>'profile'='composed-producer-record-projection-v1'))`, t.Scope.Tenant, t.Scope.Partner, f.ID, f.EventID, f.Size, f.SHA256, f.Policy, t.Actor).Scan(&projection, &hash, &policyID, &version, &policyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p, err := t.ProcessingPolicy(ctx, OnboardingReference{ID: policyID, Version: version, Hash: policyHash})
	if err != nil {
		return nil, err
	}
	b, err := t.ProcessingOutputBinding(ctx, policyID, version)
	if err != nil {
		return nil, err
	}
	actor := ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root))}
	origin, err := producedSource(f, p, b, actor, projection, hash)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(origin)
	if err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT freightctl_produced_source_current($1,$2,$3,$4,$5::jsonb)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, f.ID, raw); err != nil {
		return nil, err
	}
	return origin, nil
}
