package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	ExchangeEvidenceV1 = "authorized-exchange-evidence-v1"
	ExchangeEvidenceV2 = "authorized-exchange-evidence-v2"
	ExchangeEvidenceV3 = "authorized-exchange-evidence-v3"
	ExchangeEvidenceV4 = "authorized-exchange-evidence-v4"
)

type ExchangeTraceRequest struct {
	ID        string `json:"exchange_id"`
	Direction string `json:"direction"`
	Profile   string `json:"profile,omitempty"`
}

type ExchangeTraceExportSelection struct {
	ExchangeTraceRequest
	RequestHash string `json:"request_hash"`
}

func (r ExchangeTraceExportSelection) Validate() error {
	if !browserSecretHash.MatchString(r.RequestHash) {
		return ErrExchangeInput
	}
	return ValidateExchangeTraceRequest(r.ExchangeTraceRequest)
}

func ValidateExchangeTraceRequest(r ExchangeTraceRequest) error {
	if !ValidID(r.ID) || (r.Direction != "incoming" && r.Direction != "outgoing") {
		return ErrExchangeInput
	}
	switch r.Profile {
	case "", ExchangeEvidenceV1, ExchangeEvidenceV2, ExchangeEvidenceV3, ExchangeEvidenceV4:
		return nil
	default:
		return ErrExchangeInput
	}
}

type ExchangeTraceEvent struct {
	Kind     string    `json:"kind"`
	ID       string    `json:"event_id"`
	Resource string    `json:"resource_id"`
	At       time.Time `json:"recorded_at"`
}
type ExchangeProjectionLineage struct {
	ProjectionID   string           `json:"projection_id"`
	DefinitionHash string           `json:"definition_hash"`
	Source         ExchangeArtifact `json:"source_artifact"`
	SourceEvent    string           `json:"source_accepted_event_id"`
	CompletedEvent string           `json:"completed_event_id"`
	CompletedAt    time.Time        `json:"completed_at"`
}
type ExchangeTrace struct {
	Profile             string                     `json:"profile"`
	Tenant              string                     `json:"tenant_id"`
	Partner             string                     `json:"partner_id"`
	ID                  string                     `json:"exchange_id"`
	Direction           string                     `json:"direction"`
	State               string                     `json:"current_metadata_state"`
	CheckedAt           time.Time                  `json:"checked_at"`
	Details             string                     `json:"details"`
	RequestHash         string                     `json:"request_hash,omitempty"`
	Artifact            *ExchangeArtifact          `json:"artifact,omitempty"`
	ReplyTo             string                     `json:"reply_reference_only,omitempty"`
	Events              []ExchangeTraceEvent       `json:"recorded_events"`
	Projection          *ExchangeProjectionLineage `json:"record_projection,omitempty"`
	ReceivedCopy        *ExchangeCopyLineage       `json:"received_copy,omitempty"`
	IntegrityReport     *ExchangeIntegrityReport   `json:"integrity_report,omitempty"`
	StorageVerification string                     `json:"storage_verification"`
	Retrieval           string                     `json:"retrieval"`
	ReceiverPersistence string                     `json:"receiver_persistence"`
	BusinessProcessing  string                     `json:"business_processing"`
}

func emptyExchangeTrace(scope Scope, r ExchangeTraceRequest, state string, at time.Time) *ExchangeTrace {
	profile := r.Profile
	if profile == "" {
		profile = ExchangeEvidenceV1
	}
	return &ExchangeTrace{Profile: profile, Tenant: scope.Tenant, Partner: scope.Partner, ID: r.ID, Direction: r.Direction, State: state, CheckedAt: at.UTC(), Details: "opaque", Events: []ExchangeTraceEvent{}, StorageVerification: "not-checked", Retrieval: "unknown", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"}
}

// Direction chooses the existing incoming view or original sender authority.
// V2 can correlate one completed record projection for its original actor.
// V3 also includes the exact stored integrity report when one is available.
// V4 adds the sender's own copy provenance while the original view is readable.
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
	result, err := t.TraceExchange(ctx, r, limits)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}

func (t *Transaction) TraceExchange(ctx context.Context, r ExchangeTraceRequest, limits ExchangeLimits) (*ExchangeTrace, error) {
	var e *ArtifactExchange
	var file *File
	var state, closure string
	var checked time.Time
	var err error
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
	result := emptyExchangeTrace(t.Scope, r, state, checked)
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
		if (r.Profile == ExchangeEvidenceV2 || r.Profile == ExchangeEvidenceV3 || r.Profile == ExchangeEvidenceV4) && r.Direction == "outgoing" {
			result.Projection, err = t.exchangeProjectionLineage(ctx, file)
			if err != nil {
				return nil, err
			}
		}
		if r.Profile == ExchangeEvidenceV4 && r.Direction == "outgoing" {
			result.ReceivedCopy, err = t.exchangeCopyLineage(ctx, file, limits)
			if err != nil {
				return nil, err
			}
		}
		if r.Profile == ExchangeEvidenceV3 || r.Profile == ExchangeEvidenceV4 {
			result.IntegrityReport, err = t.exchangeIntegrityReport(ctx, e)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
		}
	}
	return result, nil
}

// The outgoing trace already holds the shared namespace lock. Bind the output
// acceptance and its private slot to the original completed projection. Use the
// reviewed input tuple and ordinary current file access before disclosing it.
func (t *Transaction) exchangeProjectionLineage(ctx context.Context, output *File) (*ExchangeProjectionLineage, error) {
	var lineage ExchangeProjectionLineage
	err := t.Tx.QueryRow(ctx, `
SELECT r.projection_id::text,r.definition_hash,f.file_id::text,f.size_bytes,f.sha256,f.policy,
       source.event_id::text,completed.event_id::text,completed.happened_at
FROM record_projection_slots s
JOIN record_projections r USING (tenant_id,partner_id,actor_id,projection_id)
JOIN events accepted ON (accepted.tenant_id,accepted.partner_id,accepted.actor_id,accepted.resource_id,accepted.kind)
                       =(r.tenant_id,r.partner_id,r.actor_id,s.file_id,'FileAccepted')
JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(r.tenant_id,r.partner_id,r.source_file_id)
JOIN events source ON (source.tenant_id,source.partner_id,source.event_id,source.resource_id,source.kind)
                     =(f.tenant_id,f.partner_id,f.accepted_event_id,f.file_id,'FileAccepted')
JOIN events completed ON (completed.tenant_id,completed.partner_id,completed.event_id,completed.actor_id,completed.resource_id,completed.kind)
                        =(r.tenant_id,r.partner_id,r.changed_event_id,r.actor_id,r.projection_id,'RecordProjectionChanged')
WHERE s.file_id=$1 AND accepted.event_id=$2 AND s.actor_id=$3 AND r.state='completed' AND r.new_file_id=s.file_id
  AND accepted.payload->>'schema_version' IN ('5','6','7')
  AND accepted.payload #>> '{record_projection,id}'=r.projection_id::text
  AND accepted.payload #>> '{record_projection,definition_hash}'=r.definition_hash
  AND accepted.payload #>> '{record_projection,source_file_id}'=f.file_id::text
  AND r.definition #>> '{plan,context,namespace_root}'=$4
  AND r.definition #> '{plan,context,authority_revision}'=to_jsonb($5::bigint)
  AND r.definition #> '{plan,context,source,file}'=jsonb_build_object(
      'id',f.file_id::text,'size_bytes',f.size_bytes,'sha256',f.sha256,'policy',f.policy,'accepted_event_id',source.event_id::text)`,
		output.ID, output.EventID, t.Actor, t.Root, t.AuthorityRevision).Scan(
		&lineage.ProjectionID, &lineage.DefinitionHash, &lineage.Source.ID, &lineage.Source.Size, &lineage.Source.SHA256,
		&lineage.Source.Policy, &lineage.SourceEvent, &lineage.CompletedEvent, &lineage.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = t.FileAccessible(ctx, lineage.Source.ID); err != nil {
		if errors.Is(err, ErrState) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrLimit) {
			return nil, nil
		}
		return nil, err
	}
	lineage.CompletedAt = lineage.CompletedAt.UTC()
	return &lineage, nil
}
