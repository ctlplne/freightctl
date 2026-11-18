package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
)

const eligibleConnectionRecipient = `namespace_root='/' AND permissions @> ARRAY['read','deliver','workflow_execute']::text[]
	AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp())`

func (t *Transaction) ConnectionAuthorityFence(ctx context.Context) error {
	_, err := t.Tx.Exec(ctx, `SELECT freightctl_authority_read_lock($1,$2)`, t.Scope.Tenant, t.Scope.Partner)
	return err
}

func (t *Transaction) CheckConnectionProvisionRecipient(ctx context.Context, id string, authority int64) error {
	var current int64
	err := t.Tx.QueryRow(ctx, `SELECT authority_revision FROM credentials
		WHERE (tenant_id,partner_id,actor_id)=($1,$2,$3) AND `+eligibleConnectionRecipient, t.Scope.Tenant, t.Scope.Partner, id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err == nil && current != authority {
		return ErrRevision
	}
	return err
}

type ConnectionProvisionRecipient struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Authority int64  `json:"authority_revision"`
}

func (t *Transaction) ConnectionProvisionRecipients(ctx context.Context, after string, count int) ([]ConnectionProvisionRecipient, error) {
	rows, err := t.Tx.Query(ctx, `SELECT actor_id::text,account_label,authority_revision FROM credentials
		WHERE (tenant_id,partner_id)=($1,$2) AND actor_id<>$3 AND ($4='' OR actor_id>nullif($4,'')::uuid)
		AND `+eligibleConnectionRecipient+` ORDER BY actor_id LIMIT $5`, t.Scope.Tenant, t.Scope.Partner, t.Actor, after, count)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ConnectionProvisionRecipient{}
	for rows.Next() {
		var r ConnectionProvisionRecipient
		if err = rows.Scan(&r.ID, &r.Label, &r.Authority); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (t *Transaction) OwnConnectionProvision(ctx context.Context, event, connection string) (json.RawMessage, error) {
	var result json.RawMessage
	err := t.Tx.QueryRow(ctx, `SELECT payload->'provision' FROM events
		WHERE (tenant_id,partner_id,actor_id,event_id,resource_id,kind)=($1,$2,$3,$4,$5,'OperatorConnectionChanged')
		AND payload->'provision'->>'operation'='provision'`, t.Scope.Tenant, t.Scope.Partner, t.Actor, event, connection).Scan(&result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return result, err
}
