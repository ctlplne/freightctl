package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// ProcessingOutputBinding fixes the one producer allowed to use this policy
// revision. It is metadata, not authentication, file access or execution rights.
// Policy shape hashes remain compatible with the ordinary check reports; the
// immutable ID/version also binds this separately journalled producer snapshot.
type ProcessingOutputBinding struct {
	Profile   string              `json:"profile"`
	PolicyID  string              `json:"policy_id"`
	Version   int                 `json:"policy_version"`
	Hash      string              `json:"policy_hash"`
	Publisher string              `json:"publisher_id"`
	Producer  ExchangeParticipant `json:"producer"`
}

func (t *Transaction) ProcessingOutputProducer(ctx context.Context, id string) (ExchangeParticipant, error) {
	p := ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner}
	var root string
	err := t.Tx.QueryRow(ctx, `SELECT actor_id::text,authority_revision,namespace_root FROM credentials WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND permissions @> ARRAY['read','write','check_run','workflow_execute']::text[] AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`, t.Scope.Tenant, t.Scope.Partner, id).Scan(&p.Actor, &p.AuthorityRevision, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.RootPolicyDigest = secure.Digest([]byte(root))
	return p, nil
}
func (t *Transaction) ProcessingOutputHead(ctx context.Context, id string, exclusive bool) (*Configuration, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	lock, suffix := "pg_advisory_xact_lock_shared", " FOR SHARE"
	if exclusive {
		lock, suffix = "pg_advisory_xact_lock", " FOR UPDATE"
	}
	if _, err := t.Tx.Exec(ctx, `SELECT `+lock+`(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":processing-output-policy:"+id); err != nil {
		return nil, err
	}
	c := &Configuration{}
	err := t.Tx.QueryRow(ctx, `SELECT policy_id::text,version,definition,definition_hash,state,revision FROM intake_policies WHERE policy_id=$1 AND state IN ('output_active','output_retired','output_revoked') ORDER BY version DESC LIMIT 1`+suffix, id).Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return c, err
}
func (t *Transaction) ProcessingOutputPolicy(ctx context.Context, id string, version int, lock bool) (*Configuration, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	c := &Configuration{}
	err := t.Tx.QueryRow(ctx, `SELECT policy_id::text,version,definition,definition_hash,state,revision FROM intake_policies WHERE policy_id=$1 AND version=$2 AND state IN ('output_active','output_retired','output_revoked')`+suffix, id, version).Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}
func (t *Transaction) ProcessingOutputBinding(ctx context.Context, id string, version int) (*ProcessingOutputBinding, error) {
	var raw []byte
	var hash string
	err := t.Tx.QueryRow(ctx, `SELECT binding,binding_hash FROM processing_output_policies WHERE policy_id=$1 AND policy_version=$2`, id, version).Scan(&raw, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var b ProcessingOutputBinding
	var trailing any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&b) != nil || decoder.Decode(&trailing) != io.EOF {
		return nil, ErrIsolation
	}
	canonical, err := json.Marshal(b)
	if err != nil || secure.Digest(canonical) != hash || b.PolicyID != id || b.Version != version {
		return nil, ErrIsolation
	}
	return &b, nil
}
func (t *Transaction) SaveProcessingOutputBinding(ctx context.Context, b *ProcessingOutputBinding) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	hash := secure.Digest(raw)
	event, err := t.Append(ctx, "ProcessingOutputPolicyBound", b.PolicyID, map[string]any{"binding": b, "binding_hash": hash})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO processing_output_policies(tenant_id,partner_id,actor_id,policy_id,policy_version,producer_id,binding,binding_hash,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, b.PolicyID, b.Version, b.Producer.Actor, raw, hash, event)
	return err
}

func (t *Transaction) ProcessingOutputPolicies(ctx context.Context, after string, limit int) ([]*Configuration, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, err := t.Tx.Query(ctx, `SELECT policy_id::text,version,definition,definition_hash,state,revision FROM intake_policies WHERE state='output_active' AND ($1='' OR policy_id>nullif($1,'')::uuid) ORDER BY policy_id LIMIT $2`, after, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]*Configuration, 0, limit+1)
	for rows.Next() {
		c := &Configuration{}
		if err = rows.Scan(&c.ID, &c.Version, &c.Definition, &c.Hash, &c.State, &c.Revision); err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	return result, rows.Err()
}
