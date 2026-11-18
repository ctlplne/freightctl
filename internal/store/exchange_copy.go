package store

import (
	"context"
	"encoding/json"
	"errors"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
)

// This is a requested exact source, not a grant. The transaction independently
// resolves the stored view and current recipient before it opens any bytes.
type ExchangeCopyOrigin struct {
	ExchangeID  string           `json:"exchange_id"`
	RequestHash string           `json:"request_hash"`
	Artifact    ExchangeArtifact `json:"artifact"`
}

type ExchangeCopyRequest struct {
	ExchangeCopyOrigin
	Path string `json:"virtual_path"`
}

func ValidateExchangeCopy(r ExchangeCopyRequest, maximum int64) error {
	p, err := vpath.Canonical(r.Path)
	if maximum < 0 || !ValidID(r.ExchangeID) || !browserSecretHash.MatchString(r.RequestHash) || !ValidID(r.Artifact.ID) || r.Artifact.Size < 0 || r.Artifact.Size > maximum || !browserSecretHash.MatchString(r.Artifact.SHA256) || len(r.Artifact.Policy) < 1 || len(r.Artifact.Policy) > 256 || err != nil || p != r.Path || p == "/" || vpath.ControlPath(p) {
		return ErrExchangeInput
	}
	return nil
}

// The root-resolved ordinary create request is included: a different receive
// view, source identity, policy, digest or destination cannot replay this key.
func ExchangeCopyMeaning(r ExchangeCopyRequest, ordinaryMeaning string) string {
	wire, _ := json.Marshal(struct {
		Profile string              `json:"profile"`
		Request ExchangeCopyRequest `json:"request"`
		Target  string              `json:"ordinary_target_meaning"`
	}{"received-artifact-copy-v1", r, ordinaryMeaning})
	return secure.Digest(wire)
}

func (t *Transaction) AcceptExchangeCopy(ctx context.Context, key, meaning string, f *File, storageID string, origin ExchangeCopyOrigin) error {
	if !ValidID(storageID) || !ValidID(origin.ExchangeID) || !browserSecretHash.MatchString(origin.RequestHash) || origin.Artifact.ID == f.ID || origin.Artifact.Size != f.Size || origin.Artifact.SHA256 != f.SHA256 {
		return ErrIsolation
	}
	return t.accept(ctx, key, meaning, f, "", storageID, &origin)
}

type ExchangeCopyLineage struct {
	Source         ExchangeCopyOrigin `json:"source"`
	SourceAccepted string             `json:"source_accepted_event_id"`
	SourceOffer    string             `json:"source_offer_event_id"`
}

// The caller has already authorized the outgoing revision. Its acceptance
// binds an owned copy to one receive view, whose authority is checked anew.
func (t *Transaction) exchangeCopyLineage(ctx context.Context, output *File, limits ExchangeLimits) (*ExchangeCopyLineage, error) {
	var origin ExchangeCopyOrigin
	err := t.Tx.QueryRow(ctx, `SELECT payload->'exchange_copy' FROM events
WHERE (event_id,resource_id,actor_id,kind)=($1,$2,$3,'FileAccepted')
  AND payload->'schema_version'='4'::jsonb`, output.EventID, output.ID, t.Actor).Scan(&origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !ValidID(origin.ExchangeID) || origin.Artifact.ID == output.ID || origin.Artifact.Size != output.Size || origin.Artifact.SHA256 != output.SHA256 {
		return nil, ErrIsolation
	}
	parent, err := t.ArtifactExchange(ctx, origin.ExchangeID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if parent.Recipient != t.Actor || parent.RequestHash != origin.RequestHash || parent.Request.Artifact != origin.Artifact {
		return nil, ErrIsolation
	}
	// Outgoing authorization already holds namespace and policy locks. Avoid
	// waiting out of order on a concurrent change to the parent view or route.
	var view, endpoint bool
	err = t.Tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0)),
pg_try_advisory_xact_lock_shared(hashtextextended($2,0))`,
		exchangeViewLock(t.Scope, parent.ID), exchangeEndpointLock(t.Scope, parent.Request.Endpoint.ID)).Scan(&view, &endpoint)
	if err != nil || !view || !endpoint {
		return nil, err
	}
	source, err := t.authorizeIncomingExchange(ctx, parent, limits)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrState) || errors.Is(err, ErrRevision) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrLimit) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !ValidID(source.EventID) || !ValidID(parent.EventID) {
		return nil, ErrIsolation
	}
	return &ExchangeCopyLineage{Source: origin, SourceAccepted: source.EventID, SourceOffer: parent.EventID}, nil
}
