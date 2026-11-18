package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const ExchangeIntegrityReportProfile = "recipient-sha256-report-v1"

type ExchangeIntegrityCommand struct {
	Schema            int    `json:"schema_version"`
	ExchangeID        string `json:"exchange_id"`
	RequestHash       string `json:"request_hash"`
	ReadAuthorization string `json:"read_authorization_event_id"`
	FileID            string `json:"file_revision_id"`
	Size              int64  `json:"size_bytes"`
	SHA256            string `json:"sha256"`
}

type ExchangeIntegrityReport struct {
	Profile             string           `json:"profile"`
	ExchangeID          string           `json:"exchange_id"`
	RequestHash         string           `json:"request_hash"`
	Artifact            ExchangeArtifact `json:"artifact"`
	ReadAuthorization   string           `json:"read_authorization_event_id"`
	Observation         string           `json:"observation"`
	EventID             string           `json:"event_id"`
	RecordedAt          time.Time        `json:"recorded_at"`
	ReceiverPersistence string           `json:"receiver_persistence"`
	BusinessProcessing  string           `json:"business_processing"`
}

func canonicalExchangeIntegrityCommand(command ExchangeIntegrityCommand) ([]byte, string, error) {
	if command.Schema != 1 || !ValidID(command.ExchangeID) || !ValidID(command.ReadAuthorization) || !ValidID(command.FileID) || command.Size < 0 ||
		!browserSecretHash.MatchString(command.RequestHash) || !browserSecretHash.MatchString(command.SHA256) {
		return nil, "", ErrExchangeInput
	}
	return exchangeCanonical(command)
}

func DecodeExchangeIntegrityCommand(raw []byte) (ExchangeIntegrityCommand, error) {
	var command ExchangeIntegrityCommand
	if err := decodeExchangeJSONBound(raw, &command, 4096); err != nil {
		return command, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 7 {
		return command, ErrExchangeInput
	}
	_, _, err := canonicalExchangeIntegrityCommand(command)
	return command, err
}

// RecordExchangeIntegrityReport records the participant's statement about the
// digest and length. The earlier read authorization is a prerequisite only.
func (s *Store) RecordExchangeIntegrityReport(ctx context.Context, scope Scope, key string, c ExchangeIntegrityCommand, limits ExchangeLimits) (*ExchangeIntegrityReport, bool, error) {
	wire, hash, err := canonicalExchangeIntegrityCommand(c)
	if err != nil || !ValidBrowserOperationKey(key) || !limits.valid() {
		return nil, false, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, false, err
	}
	defer tx.Tx.Rollback(ctx)
	// The same recipient key cannot race across two views. Live authority and
	// the shared view lock hold through insertion of the original receipt.
	if _, err = tx.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+tx.Actor+":exchange-integrity-command"); err != nil {
		return nil, false, err
	}
	e, f, err := tx.AuthorizeIncomingExchange(ctx, c.ExchangeID, limits)
	if err != nil {
		return nil, false, err
	}
	var priorID, priorHash string
	err = tx.Tx.QueryRow(ctx, `SELECT exchange_id::text,command_hash FROM artifact_exchange_integrity_reports WHERE actor_id=$1 AND request_key=$2`, tx.Actor, key).Scan(&priorID, &priorHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, false, err
	}
	replayed := err == nil
	if replayed && (priorID != e.ID || priorHash != hash) {
		return nil, false, ErrConflict
	}
	if !replayed {
		if c.RequestHash != e.RequestHash || c.FileID != f.ID || c.Size != f.Size || c.SHA256 != f.SHA256 {
			return nil, false, ErrRevision
		}
		var eligible bool
		err = tx.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM events WHERE event_id=$1 AND actor_id=$2 AND resource_id=$3 AND kind='ArtifactExchangeRetrievalAuthorized' AND payload=jsonb_build_object('file_revision_id',$4::text,'sha256',$5::text,'evidence','read-authorized-only','report_profile',$6::text))`, c.ReadAuthorization, tx.Actor, e.ID, f.ID, f.SHA256, ExchangeIntegrityReportProfile).Scan(&eligible)
		if err != nil {
			return nil, false, err
		}
		if !eligible {
			return nil, false, ErrNotFound
		}
		if _, err = tx.exchangeIntegrityReport(ctx, e); !errors.Is(err, ErrNotFound) {
			if err == nil {
				err = ErrConflict
			}
			return nil, false, err
		}
		event, err := tx.Append(ctx, "ArtifactExchangeIntegrityReported", e.ID, map[string]any{
			"command_hash": hash, "request_key": key, "command": json.RawMessage(wire),
		})
		if err != nil {
			return nil, false, err
		}
		_, err = tx.Tx.Exec(ctx, `INSERT INTO artifact_exchange_integrity_reports(tenant_id,partner_id,exchange_id,actor_id,request_key,command_wire,command_hash,read_event_id,event_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, scope.Tenant, scope.Partner, e.ID, tx.Actor, key, string(wire), hash, c.ReadAuthorization, event)
		if err != nil {
			return nil, false, err
		}
	}
	result, err := tx.exchangeIntegrityReport(ctx, e)
	if err != nil {
		return nil, false, err
	}
	if err = tx.Reauthorize(ctx); err != nil {
		return nil, false, err
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		return nil, false, err
	}
	return result, replayed, nil
}

func (s *Store) InspectExchangeIntegrityReport(ctx context.Context, scope Scope, request ExchangeTraceRequest, limits ExchangeLimits) (*ExchangeIntegrityReport, error) {
	if request.Profile != "" || ValidateExchangeTraceRequest(request) != nil || !limits.valid() {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	var e *ArtifactExchange
	if request.Direction == "incoming" {
		e, _, err = tx.AuthorizeIncomingExchange(ctx, request.ID, limits)
	} else {
		var outgoing *OutgoingExchange
		outgoing, err = tx.outgoingExchange(ctx, request.ID)
		if err == nil {
			e = &outgoing.Exchange
		}
	}
	if err != nil {
		return nil, err
	}
	result, err := tx.exchangeIntegrityReport(ctx, e)
	if err != nil {
		return nil, err
	}
	if err = tx.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, tx.Tx.Commit(ctx)
}

func (t *Transaction) exchangeIntegrityReport(ctx context.Context, e *ArtifactExchange) (*ExchangeIntegrityReport, error) {
	result := &ExchangeIntegrityReport{
		Profile: ExchangeIntegrityReportProfile, ExchangeID: e.ID, RequestHash: e.RequestHash, Artifact: e.Request.Artifact,
		Observation: "recipient-reported-sha256-and-length-match", ReceiverPersistence: "unknown", BusinessProcessing: "unknown",
	}
	err := t.Tx.QueryRow(ctx, `SELECT r.read_event_id::text,r.event_id::text,j.happened_at FROM artifact_exchange_integrity_reports r
 JOIN events j ON (j.tenant_id,j.partner_id,j.event_id)=(r.tenant_id,r.partner_id,r.event_id) WHERE r.exchange_id=$1`, e.ID).
		Scan(&result.ReadAuthorization, &result.EventID, &result.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	result.RecordedAt = result.RecordedAt.UTC()
	return result, nil
}
