package store

import (
	"bytes"
	"context"
	"time"
)

type ExchangeEndpointPage struct {
	Endpoints []ExchangeEndpointVersion `json:"endpoints"`
	Next      string                    `json:"next,omitempty"`
}

func validExchangeEndpointRecord(e *ExchangeEndpointVersion, scope Scope) error {
	if e == nil || !ValidID(e.ID) || e.Revision < 1 || !ValidID(e.RecordedBy) || !ValidID(e.EventID) || e.State != "active" && e.State != "revoked" {
		return ErrIsolation
	}
	// Reading a journal record uses structural bounds, not today's lower
	// admission limit. Displaying it grants no authority to publish or retrieve.
	d, canonical, hash, err := DecodeExchangeEndpoint(e.Definition, ExchangeLimits{MaxArtifactBytes: 0, MaxLifetime: time.Second, MaxSenders: 128})
	if err != nil || hash != e.Hash || !bytes.Equal(canonical, e.Definition) || d.Recipient.Tenant != scope.Tenant || d.Recipient.Partner != scope.Partner {
		return ErrIsolation
	}
	return nil
}

func (s *Store) ExchangeEndpoint(ctx context.Context, scope Scope, id string) (*ExchangeEndpointVersion, error) {
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
	e, err := t.CurrentExchangeEndpoint(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = validExchangeEndpointRecord(e, scope); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return e, t.Tx.Commit(ctx)
}

func (s *Store) ExchangeEndpoints(ctx context.Context, scope Scope, after string, limit int) (*ExchangeEndpointPage, error) {
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
	// Heads apply current participant RLS; historical versions cannot become a
	// directory entry after a sender is removed or its authority changes.
	rows, err := t.Tx.Query(ctx, `SELECT endpoint_id::text FROM exchange_endpoint_heads WHERE ($1='' OR endpoint_id>nullif($1,'')::uuid) ORDER BY endpoint_id LIMIT $2`, after, limit+1)
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
	page := &ExchangeEndpointPage{Endpoints: make([]ExchangeEndpointVersion, 0, limit)}
	for i, id := range ids {
		// Lock/recheck the extra entry too: an unvalidated row cannot determine
		// whether the caller learns there is another page.
		e, err := t.CurrentExchangeEndpoint(ctx, id)
		if err != nil {
			return nil, err
		}
		if err = validExchangeEndpointRecord(e, scope); err != nil {
			return nil, err
		}
		if i < limit {
			page.Endpoints = append(page.Endpoints, *e)
		}
	}
	if len(ids) > limit {
		page.Next = page.Endpoints[len(page.Endpoints)-1].ID
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
