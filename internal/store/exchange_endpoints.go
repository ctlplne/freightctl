package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type ExchangeEndpointCommand struct {
	Operation        string                      `json:"operation"`
	ID               string                      `json:"endpoint_id"`
	ExpectedRevision int64                       `json:"expected_revision"`
	Definition       *ExchangeEndpointDefinition `json:"definition,omitempty"`
}

type ExchangeEndpointVersion struct {
	ID         string          `json:"id"`
	Revision   int64           `json:"revision"`
	Definition json.RawMessage `json:"definition"`
	Hash       string          `json:"definition_hash"`
	State      string          `json:"state"`
	RecordedBy string          `json:"recorded_by"`
	EventID    string          `json:"event_id,omitempty"`
}

type ExchangeEndpointResult struct {
	Endpoint ExchangeEndpointVersion `json:"endpoint"`
	Replayed bool                    `json:"replayed"`
}

func DecodeExchangeEndpointCommand(raw []byte, limits ExchangeLimits) (*ExchangeEndpointCommand, error) {
	var command ExchangeEndpointCommand
	if err := decodeExchangeJSONBound(raw, &command, 24<<10); err != nil {
		return nil, err
	}
	normalized, _, err := canonicalExchangeEndpointCommand(command, limits)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func canonicalExchangeEndpointCommand(c ExchangeEndpointCommand, limits ExchangeLimits) (ExchangeEndpointCommand, string, error) {
	if !limits.valid() || !ValidID(c.ID) || c.ExpectedRevision < 0 || c.ExpectedRevision == 1<<63-1 {
		return c, "", ErrExchangeInput
	}
	switch c.Operation {
	case "create":
		if c.ExpectedRevision != 0 || c.Definition == nil {
			return c, "", ErrExchangeInput
		}
	case "replace":
		if c.ExpectedRevision < 1 || c.Definition == nil {
			return c, "", ErrExchangeInput
		}
	case "revoke":
		if c.ExpectedRevision < 1 || c.Definition != nil {
			return c, "", ErrExchangeInput
		}
	default:
		return c, "", ErrExchangeInput
	}
	if c.Definition != nil {
		data, _, err := CanonicalExchangeEndpoint(*c.Definition, limits)
		if err != nil {
			return c, "", err
		}
		var independent ExchangeEndpointDefinition
		if json.Unmarshal(data, &independent) != nil {
			return c, "", ErrExchangeInput
		}
		c.Definition = &independent
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > 24<<10 {
		return c, "", ErrExchangeInput
	}
	return c, secure.Digest(data), nil
}

// RegisterExchangeEndpoint changes only a registered custody view. It neither
// moves bytes nor grants a credential, forwarding right or execution permission.
func (s *Store) RegisterExchangeEndpoint(ctx context.Context, scope Scope, key string, command ExchangeEndpointCommand, limits ExchangeLimits, maximum int) (*ExchangeEndpointResult, error) {
	c, meaning, err := canonicalExchangeEndpointCommand(command, limits)
	if err != nil || !ValidBrowserOperationKey(key) || maximum < 1 || maximum > 10000 {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Reuse account-management lock order. Pin credentials after obtaining
	// manager serialization, so rotation cannot interleave registration.
	t, err := s.beginAuthenticated(ctx, scope, pgx.TxOptions{}, true)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.requireAccountManager(); err != nil {
		return nil, err
	}
	var previousHash string
	var receipt []byte
	err = t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM exchange_endpoint_commands WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&previousHash, &receipt)
	if err == nil {
		if previousHash != meaning {
			return nil, ErrConflict
		}
		var result ExchangeEndpointResult
		if json.Unmarshal(receipt, &result) != nil {
			return nil, ErrIsolation
		}
		result.Replayed = true
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		if err = t.requireAccountManager(); err != nil {
			return nil, err
		}
		return &result, t.Tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, exchangeEndpointLock(scope, c.ID)); err != nil {
		return nil, err
	}
	old, err := t.exchangeEndpointVersion(ctx, c.ID)
	if c.Operation == "create" {
		if err == nil {
			return nil, ErrExists
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		var count int
		if err = t.Tx.QueryRow(ctx, `SELECT count(DISTINCT endpoint_id) FROM exchange_endpoint_versions`).Scan(&count); err != nil {
			return nil, err
		}
		if count >= maximum {
			return nil, ErrLimit
		}
	} else {
		if err != nil {
			return nil, err
		}
		if old.Revision != c.ExpectedRevision {
			return nil, ErrRevision
		}
		if old.State != "active" {
			return nil, ErrState
		}
	}
	endpoint := ExchangeEndpointVersion{ID: c.ID, Revision: c.ExpectedRevision + 1, State: "active", RecordedBy: t.Actor}
	if c.Operation == "revoke" {
		endpoint.Definition, endpoint.Hash, endpoint.State = old.Definition, old.Hash, "revoked"
	} else {
		if err = t.validateExchangeEndpointParticipants(ctx, *c.Definition); err != nil {
			return nil, err
		}
		endpoint.Definition, endpoint.Hash, err = CanonicalExchangeEndpoint(*c.Definition, limits)
		if err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.requireAccountManager(); err != nil {
		return nil, err
	}
	endpoint.EventID, err = t.Append(ctx, "ExchangeEndpointRecorded", c.ID, endpoint)
	if err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO exchange_endpoint_versions(tenant_id,partner_id,endpoint_id,revision,definition,definition_wire,definition_hash,state,recorded_by,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, scope.Tenant, scope.Partner, endpoint.ID, endpoint.Revision, endpoint.Definition, string(endpoint.Definition), endpoint.Hash, endpoint.State, t.Actor, endpoint.EventID); err != nil {
		return nil, err
	}
	result := &ExchangeEndpointResult{Endpoint: endpoint}
	event, err := t.Append(ctx, "ExchangeEndpointCommandCompleted", c.ID, map[string]any{"request_key": key, "request_hash": meaning, "command": map[string]any{"operation": c.Operation, "endpoint_id": c.ID, "expected_revision": c.ExpectedRevision}, "result": result})
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO exchange_endpoint_commands(tenant_id,partner_id,actor_id,request_key,request_hash,endpoint_id,revision,result,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.Tenant, scope.Partner, t.Actor, key, meaning, c.ID, endpoint.Revision, data, event); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}

func exchangeEndpointLock(scope Scope, id string) string {
	return scope.Tenant + ":" + scope.Partner + ":exchange-endpoint:" + id
}

// CurrentExchangeEndpoint must be used for consequential work. Historical
// versions can remain visible to an old participant; only the head determines
// which version is current, and its RLS checks the current participant bindings.
func (t *Transaction) CurrentExchangeEndpoint(ctx context.Context, id string) (*ExchangeEndpointVersion, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, exchangeEndpointLock(t.Scope, id)); err != nil {
		return nil, err
	}
	var e ExchangeEndpointVersion
	var wire string
	err := t.Tx.QueryRow(ctx, `SELECT v.endpoint_id::text,v.revision,v.definition_wire,v.definition_hash,v.state,v.recorded_by::text,v.event_id::text FROM exchange_endpoint_heads h JOIN exchange_endpoint_versions v USING(tenant_id,partner_id,endpoint_id,revision) WHERE h.endpoint_id=$1`, id).Scan(&e.ID, &e.Revision, &wire, &e.Hash, &e.State, &e.RecordedBy, &e.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if secure.Digest([]byte(wire)) != e.Hash {
		return nil, ErrIsolation
	}
	e.Definition = json.RawMessage(wire)
	return &e, nil
}

func (t *Transaction) exchangeEndpointVersion(ctx context.Context, id string) (*ExchangeEndpointVersion, error) {
	var e ExchangeEndpointVersion
	var wire string
	err := t.Tx.QueryRow(ctx, `SELECT endpoint_id::text,revision,definition_wire,definition_hash,state,recorded_by::text,event_id::text FROM exchange_endpoint_versions WHERE endpoint_id=$1 ORDER BY revision DESC LIMIT 1`, id).Scan(&e.ID, &e.Revision, &wire, &e.Hash, &e.State, &e.RecordedBy, &e.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if secure.Digest([]byte(wire)) != e.Hash {
		return nil, ErrIsolation
	}
	e.Definition = json.RawMessage(wire)
	return &e, nil
}

func (t *Transaction) validateExchangeEndpointParticipants(ctx context.Context, d ExchangeEndpointDefinition) error {
	if t.Tx == nil {
		return ErrIsolation
	}
	// Ordinary send/receive transactions need a shared authority fence, not
	// account-management authority. Registration already owns the matching
	// exclusive fence; the SQL function safely reuses it in that transaction.
	if _, err := t.Tx.Exec(ctx, `SELECT freightctl_authority_read_lock($1,$2)`, t.Scope.Tenant, t.Scope.Partner); err != nil {
		return err
	}
	bindings := append([]ExchangeParticipant{d.Recipient}, d.Senders...)
	// Credential reads cannot interleave account changes while this fence lives.
	for i, p := range bindings {
		if p.Tenant != t.Scope.Tenant || p.Partner != t.Scope.Partner {
			return ErrNotFound
		}
		permissions := []string{"read", "deliver"}
		if i == 0 {
			permissions = []string{"read", "list"}
		}
		var current bool
		err := t.Tx.QueryRow(ctx, `SELECT authority_revision=$2 AND encode(sha256(convert_to(namespace_root,'UTF8')),'hex')=$3 AND permissions @> $4::text[] AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FROM credentials WHERE tenant_id=$5 AND partner_id=$6 AND actor_id=$1`, p.Actor, p.AuthorityRevision, p.RootPolicyDigest, permissions, t.Scope.Tenant, t.Scope.Partner).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !current {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
	}
	return nil
}
