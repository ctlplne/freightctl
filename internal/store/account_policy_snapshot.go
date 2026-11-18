package store

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
)

type AccountPolicySnapshot struct {
	Policy            AccountPolicy `json:"policy"`
	AuthorityRevision int64         `json:"authority_revision"`
	Revoked           bool          `json:"revoked"`
	Operation         string        `json:"operation"`
	EventID           *string       `json:"event_id"`
}

// AccountPolicyForExport uses the account manager's existing history and
// projection scopes. Both queries select only portable policy metadata.
func (t *Transaction) AccountPolicyForExport(ctx context.Context, id string, revision int64) (*AccountPolicySnapshot, error) {
	if !ValidID(id) || revision < 1 {
		return nil, ErrAccountInput
	}
	if err := t.requireAccountManager(); err != nil {
		return nil, err
	}
	v := &AccountPolicySnapshot{}
	scan := func(row pgx.Row) error {
		return row.Scan(&v.Policy.Label, &v.Policy.Permissions, &v.Policy.Root, &v.Policy.ExpiresAt,
			&v.AuthorityRevision, &v.Revoked, &v.Operation, &v.EventID)
	}
	err := scan(t.Tx.QueryRow(ctx, `SELECT definition->>'label',
		ARRAY(SELECT jsonb_array_elements_text(definition->'permissions')), definition->>'namespace_root',
		(definition->>'expires_at')::timestamptz, authority_revision, (definition->>'revoked')::boolean, operation, event_id::text
		FROM account_revisions WHERE account_id=$1 AND revision=$2 AND manager_actor_id=$3`, id, revision, t.Actor))
	if errors.Is(err, pgx.ErrNoRows) {
		// Bootstrap accounts and revisions private to another manager may
		// still be exported using the ordinary current account projection.
		err = scan(t.Tx.QueryRow(ctx, `SELECT account_label,permissions,namespace_root,expires_at,authority_revision,
			revoked_at IS NOT NULL,'current_snapshot',account_event_id::text FROM credentials WHERE actor_id=$1 AND account_revision=$2`,
			id, revision))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if v.AuthorityRevision < 1 || (v.EventID != nil && !ValidID(*v.EventID)) {
		return nil, ErrState
	}
	slices.Sort(v.Policy.Permissions)
	if v.Policy.ExpiresAt != nil {
		utc := v.Policy.ExpiresAt.UTC()
		v.Policy.ExpiresAt = &utc
	}
	return v, nil
}
