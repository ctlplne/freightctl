package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type ExchangeTraceRequest struct {
	ID        string `json:"exchange_id"`
	Direction string `json:"direction"`
}

func ValidateExchangeTraceRequest(r ExchangeTraceRequest) error {
	if !ValidID(r.ID) || (r.Direction != "incoming" && r.Direction != "outgoing") {
		return ErrExchangeInput
	}
	return nil
}

type ExchangeTraceEvent struct {
	Kind     string    `json:"kind"`
	ID       string    `json:"event_id"`
	Resource string    `json:"resource_id"`
	At       time.Time `json:"recorded_at"`
}
type ExchangeTrace struct {
	Profile             string               `json:"profile"`
	Tenant              string               `json:"tenant_id"`
	Partner             string               `json:"partner_id"`
	ID                  string               `json:"exchange_id"`
	Direction           string               `json:"direction"`
	State               string               `json:"current_metadata_state"`
	CheckedAt           time.Time            `json:"checked_at"`
	Details             string               `json:"details"`
	RequestHash         string               `json:"request_hash,omitempty"`
	Artifact            *ExchangeArtifact    `json:"artifact,omitempty"`
	ReplyTo             string               `json:"reply_reference_only,omitempty"`
	Events              []ExchangeTraceEvent `json:"recorded_events"`
	StorageVerification string               `json:"storage_verification"`
	Retrieval           string               `json:"retrieval"`
	ReceiverPersistence string               `json:"receiver_persistence"`
	BusinessProcessing  string               `json:"business_processing"`
}

func emptyExchangeTrace(scope Scope, r ExchangeTraceRequest, state string, at time.Time) *ExchangeTrace {
	return &ExchangeTrace{Profile: "authorized-exchange-evidence-v1", Tenant: scope.Tenant, Partner: scope.Partner, ID: r.ID, Direction: r.Direction, State: state, CheckedAt: at.UTC(), Details: "opaque", Events: []ExchangeTraceEvent{}, StorageVerification: "not-checked", Retrieval: "unknown", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}
}

// Direction chooses the existing authority boundary;there is no sender/receiver
// fallback. Only timestamps of already authorized immutable resource events are
// read. No raw payload,arbitrary event selector,parent traversal or byte grant.
func (s *Store) TraceExchange(ctx context.Context, scope Scope, r ExchangeTraceRequest, limits ExchangeLimits) (*ExchangeTrace, error) {
	if err := ValidateExchangeTraceRequest(r); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	var e *ArtifactExchange
	var file *File
	var state, closure string
	var checked time.Time
	if r.Direction == "incoming" {
		e, file, err = t.AuthorizeIncomingExchange(ctx, r.ID, limits)
		if err != nil && !errors.Is(err, ErrState) {
			return nil, err
		}
		if e == nil {
			return nil, ErrIsolation
		}
		expires := e.Request.ExpiresAt
		state = "offered"
		if errors.Is(err, ErrState) {
			e = nil
			file = nil
			state = "held"
		}
		checked, err = t.DatabaseTime(ctx)
		if err != nil {
			return nil, err
		}
		if !expires.After(checked) {
			return nil, ErrNotFound
		}
	} else {
		outgoing, err := t.outgoingExchange(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		e = &outgoing.Exchange
		state = outgoing.State
		closure = outgoing.ClosureEvent
		checked = outgoing.CheckedAt
		file, err = t.File(ctx, e.Request.Artifact.ID)
		if err != nil {
			return nil, err
		}
	}
	result := emptyExchangeTrace(scope, r, state, checked)
	if e != nil {
		if file == nil || file.ID != e.Request.Artifact.ID || file.Size != e.Request.Artifact.Size || file.SHA256 != e.Request.Artifact.SHA256 || file.Policy != e.Request.Artifact.Policy {
			return nil, ErrIsolation
		}
		result.Details = "authorized-records"
		result.RequestHash = e.RequestHash
		artifact := e.Request.Artifact
		result.Artifact = &artifact
		result.ReplyTo = e.Request.ReplyTo
		appendEvent := func(kind, eventKind, event, resource string) error {
			if !ValidID(event) || !ValidID(resource) {
				return ErrIsolation
			}
			var at time.Time
			if err := t.Tx.QueryRow(ctx, `SELECT happened_at FROM events WHERE event_id=$1 AND resource_id=$2 AND kind=$3`, event, resource, eventKind).Scan(&at); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrIsolation
				}
				return err
			}
			result.Events = append(result.Events, ExchangeTraceEvent{Kind: kind, ID: event, Resource: resource, At: at.UTC()})
			return nil
		}
		if err = appendEvent("custody-acceptance", "FileAccepted", file.EventID, file.ID); err != nil {
			return nil, err
		}
		if err = appendEvent("availability-offer", "ArtifactExchangeOffered", e.EventID, e.ID); err != nil {
			return nil, err
		}
		if closure != "" {
			if state != "canceled" && state != "declined" {
				return nil, ErrIsolation
			}
			if err = appendEvent("view-"+state, "ArtifactExchangeClosed", closure, e.ID); err != nil {
				return nil, err
			}
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}
