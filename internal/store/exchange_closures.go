package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Closing a view revokes future reads. It cannot recall bytes already read,
// delete the source, cancel other views, or assert receiver processing.
type ExchangeClosureCommand struct {
	Schema      int    `json:"schema_version"`
	ID          string `json:"exchange_id"`
	RequestHash string `json:"request_hash"`
	Operation   string `json:"operation"`
}

type ExchangeClosureResult struct {
	ID          string `json:"exchange_id"`
	State       string `json:"state"`
	CommandHash string `json:"command_hash"`
	EventID     string `json:"event_id"`
	Replayed    bool   `json:"replayed"`
}

func CanonicalExchangeClosure(c ExchangeClosureCommand) ([]byte, string, error) {
	if c.Schema != 1 || !ValidID(c.ID) || !browserSecretHash.MatchString(c.RequestHash) || c.Operation != "cancel" && c.Operation != "decline" {
		return nil, "", ErrExchangeInput
	}
	return exchangeCanonical(c)
}

func DecodeExchangeClosure(raw []byte) (*ExchangeClosureCommand, error) {
	var c ExchangeClosureCommand
	if err := decodeExchangeJSONBound(raw, &c, 4096); err != nil {
		return nil, err
	}
	if _, _, err := CanonicalExchangeClosure(c); err != nil {
		return nil, err
	}
	return &c, nil
}

func exchangeViewLock(scope Scope, id string) string {
	return scope.Tenant + ":" + scope.Partner + ":artifact-exchange:" + id
}

// Serialize cancellation against each bounded read, not the entire download.
// Once cancellation commits, already-open readers must obtain a new grant and
// fail before emitting another chunk. A chunk authorized earlier may finish.
func (t *Transaction) exchangeViewReadLock(ctx context.Context, id string) error {
	_, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, exchangeViewLock(t.Scope, id))
	return err
}

// Check only the acting participant's original stamp. A broken destination,
// held file or expired offer must not prevent its still-authorized sender from
// withdrawing it. This check grants no source bytes or historical metadata.
func (t *Transaction) authorizeExchangeClosure(ctx context.Context, e *ArtifactExchange, operation string) error {
	if e == nil || operation == "cancel" && e.Sender != t.Actor || operation == "decline" && e.Recipient != t.Actor {
		return ErrNotFound
	}
	permissions := []string{"read", "deliver"}
	if operation == "decline" {
		permissions = []string{"read", "list"}
	}
	for _, p := range permissions {
		if err := t.Require(p); err != nil {
			return err
		}
	}
	var wire string
	err := t.Tx.QueryRow(ctx, `SELECT definition_wire FROM exchange_endpoint_versions WHERE endpoint_id=$1 AND revision=$2 AND definition_hash=$3`, e.Request.Endpoint.ID, e.Request.Endpoint.Revision, e.Request.Endpoint.Hash).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	d, _, hash, err := DecodeExchangeEndpoint([]byte(wire), ExchangeLimits{MaxLifetime: time.Second, MaxSenders: 128})
	if err != nil || hash != e.Request.Endpoint.Hash {
		return ErrIsolation
	}
	if operation == "decline" {
		if d.Recipient != t.exchangeParticipant() {
			return ErrNotFound
		}
	} else if _, err = exchangeSender(*d, t.exchangeParticipant()); err != nil {
		return err
	}
	return nil
}

func (s *Store) CloseExchange(ctx context.Context, scope Scope, key string, command ExchangeClosureCommand) (*ExchangeClosureResult, error) {
	_, meaning, err := CanonicalExchangeClosure(command)
	if err != nil || !ValidBrowserOperationKey(key) {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	// Lock actor/key first so the same key cannot race across different views.
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":exchange-closure-commands"); err != nil {
		return nil, err
	}
	var previous, previousID string
	err = t.Tx.QueryRow(ctx, `SELECT command_hash,exchange_id::text FROM artifact_exchange_closure_commands WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&previous, &previousID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil && (previous != meaning || previousID != command.ID) {
		return nil, ErrConflict
	}
	replay := err == nil
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, exchangeViewLock(scope, command.ID)); err != nil {
		return nil, err
	}
	e, err := t.ArtifactExchange(ctx, command.ID)
	if err != nil {
		return nil, err
	}
	if err = t.authorizeExchangeClosure(ctx, e, command.Operation); err != nil {
		return nil, err
	}
	if e.RequestHash != command.RequestHash {
		return nil, ErrRevision
	}
	result := &ExchangeClosureResult{ID: command.ID, State: "canceled", CommandHash: meaning, Replayed: replay}
	if command.Operation == "decline" {
		result.State = "declined"
	}
	if replay {
		if err = t.Tx.QueryRow(ctx, `SELECT event_id::text FROM artifact_exchange_closure_commands WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&result.EventID); err != nil {
			return nil, err
		}
	} else {
		var closed bool
		if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM artifact_exchange_closures WHERE exchange_id=$1)`, command.ID).Scan(&closed); err != nil {
			return nil, err
		}
		if closed {
			return nil, ErrState
		}
		participant := t.exchangeParticipant()
		result.EventID, err = t.Append(ctx, "ArtifactExchangeClosed", command.ID, map[string]any{"command": command, "command_hash": meaning, "request_key": key, "participant": participant})
		if err != nil {
			return nil, err
		}
		binding, err := json.Marshal(participant)
		if err != nil {
			return nil, err
		}
		if _, err = t.Tx.Exec(ctx, `INSERT INTO artifact_exchange_closures(tenant_id,partner_id,exchange_id,actor_id,request_hash,operation,command_hash,participant,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.Tenant, scope.Partner, command.ID, t.Actor, command.RequestHash, command.Operation, meaning, binding, result.EventID); err != nil {
			return nil, err
		}
		if _, err = t.Tx.Exec(ctx, `INSERT INTO artifact_exchange_closure_commands(tenant_id,partner_id,actor_id,request_key,command_hash,exchange_id,event_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, scope.Tenant, scope.Partner, t.Actor, key, meaning, command.ID, result.EventID); err != nil {
			return nil, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}
