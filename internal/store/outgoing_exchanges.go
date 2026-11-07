package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Outgoing history is an original publication receipt and a current metadata
// check, never a grant to retrieve bytes or evidence that a receiver processed them.
type OutgoingExchange struct {
	Tenant              string           `json:"tenant_id"`
	Partner             string           `json:"partner_id"`
	Exchange            ArtifactExchange `json:"exchange"`
	State               string           `json:"state"`
	CheckedAt           time.Time        `json:"checked_at"`
	ClosureEvent        string           `json:"closure_event_id,omitempty"`
	Retrieval           string           `json:"retrieval"`
	ReceiverPersistence string           `json:"receiver_persistence"`
	BusinessProcessing  string           `json:"business_processing"`
}
type OutgoingExchangePage struct {
	Exchanges []OutgoingExchange `json:"exchanges"`
	Next      string             `json:"next,omitempty"`
}

func outgoingExchangeState(now, expires time.Time, operation string, principals, available bool) (string, error) {
	switch operation {
	case "cancel":
		return "canceled", nil
	case "decline":
		return "declined", nil
	case "":
	default:
		return "", ErrIsolation
	}
	if !expires.After(now) {
		return "expired", nil
	}
	if !principals {
		return "unavailable", nil
	}
	if !available {
		return "held", nil
	}
	return "offered", nil
}

func (t *Transaction) outgoingExchange(ctx context.Context, id string) (*OutgoingExchange, error) {
	if err := t.exchangeViewReadLock(ctx, id); err != nil {
		return nil, err
	}
	e, err := t.ArtifactExchange(ctx, id)
	if err != nil {
		return nil, err
	}
	// Preserve the same lock order as byte reads. Never expose the current head
	// here: a removed sender may still read its own authorized historical receipt.
	if _, err = t.CurrentExchangeEndpoint(ctx, e.Request.Endpoint.ID); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// Admission settings cannot hide an old record. Structural parsing still
	// verifies its exact immutable endpoint hash and original participant stamp.
	if err = t.authorizeExchangeSenderRecord(ctx, e, ExchangeLimits{MaxLifetime: time.Second, MaxSenders: 128}); err != nil {
		return nil, err
	}
	policy, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	f, err := t.File(ctx, e.Request.Artifact.ID)
	if err != nil {
		return nil, err
	}
	if e.Request.Artifact != (ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}) {
		return nil, ErrIsolation
	}
	availableErr := t.FileAvailable(ctx, f.ID)
	if availableErr != nil && !errors.Is(availableErr, ErrState) {
		return nil, availableErr
	}
	if err = t.exchangeFilePolicyCurrent(ctx, f, policy); err != nil {
		availableErr = err
	}
	var operation, closureEvent string
	err = t.Tx.QueryRow(ctx, `SELECT operation,event_id::text FROM artifact_exchange_closures WHERE exchange_id=$1`, id).Scan(&operation, &closureEvent)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var current bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_artifact_exchange_principals_current(e) FROM artifact_exchanges e WHERE exchange_id=$1`, id).Scan(&current); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	state, err := outgoingExchangeState(now, e.Request.ExpiresAt, operation, current, availableErr == nil)
	if err != nil {
		return nil, err
	}
	return &OutgoingExchange{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Exchange: *e, State: state, CheckedAt: now.UTC(), ClosureEvent: closureEvent, Retrieval: "unknown", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}, nil
}

func (s *Store) OutgoingExchange(ctx context.Context, scope Scope, id string) (*OutgoingExchange, error) {
	if !ValidID(id) {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	result, err := t.outgoingExchange(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}

func (s *Store) OutgoingExchanges(ctx context.Context, scope Scope, after string, limit int) (*OutgoingExchangePage, error) {
	if after != "" && !ValidID(after) || limit < 1 || limit > 100 {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, p := range []string{"read", "deliver", "list"} {
		if err = t.Require(p); err != nil {
			return nil, err
		}
	}
	// Filter before selecting any ID/cursor. Recheck every row, including the
	// extra row, under locks before disclosing the page. No actor impersonation.
	rows, err := t.Tx.Query(ctx, `SELECT e.exchange_id::text FROM artifact_exchanges e JOIN exchange_endpoint_versions v ON (v.tenant_id,v.partner_id,v.endpoint_id,v.revision,v.definition_hash)=(e.tenant_id,e.partner_id,e.endpoint_id,e.endpoint_revision,e.request->'endpoint'->>'hash') WHERE e.sender_actor_id=$1 AND freightctl_exchange_actor_source_readable(e.tenant_id,e.partner_id,e.file_id,e.sender_actor_id) AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.definition->'senders') p WHERE p->>'actor_id'=e.sender_actor_id::text AND freightctl_exchange_participant_current(e.tenant_id,e.partner_id,p,ARRAY['read','deliver'])) AND ($2='' OR e.exchange_id>nullif($2,'')::uuid) ORDER BY e.exchange_id LIMIT $3`, t.Actor, after, limit+1)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	page := &OutgoingExchangePage{Exchanges: make([]OutgoingExchange, 0, limit)}
	for _, id := range ids {
		entry, err := t.outgoingExchange(ctx, id)
		if err != nil {
			return nil, err
		}
		page.Exchanges = append(page.Exchanges, *entry)
	}
	if len(page.Exchanges) > limit {
		page.Next = page.Exchanges[limit-1].Exchange.ID
		page.Exchanges = page.Exchanges[:limit]
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
