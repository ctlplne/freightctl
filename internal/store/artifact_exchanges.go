package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

// ArtifactExchange records a published, revocable receive view. Its receipt
// promises availability under live checks, never retrieval or business processing.
// StorageID stays in the internal custody/event binding, outside public results.
type ArtifactExchange struct {
	ID          string          `json:"id"`
	Sender      string          `json:"sender_actor_id"`
	Recipient   string          `json:"recipient_actor_id"`
	Request     ExchangeRequest `json:"request"`
	RequestHash string          `json:"request_hash"`
	EventID     string          `json:"event_id,omitempty"`
	StorageID   string          `json:"-"`
}

type ArtifactExchangeResult struct {
	Exchange ArtifactExchange `json:"exchange"`
	Replayed bool             `json:"replayed"`
}

// Next is pagination within one polling cycle, not a new-arrival checkpoint.
// Each new poll starts without Next, so concurrent lower UUIDs are not lost.
type ArtifactExchangePage struct {
	Exchanges []IncomingExchange `json:"exchanges"`
	Next      string             `json:"next,omitempty"`
}

type IncomingExchange struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Exchange *ArtifactExchange `json:"exchange,omitempty"`
}

func (t *Transaction) exchangeParticipant() ExchangeParticipant {
	return ExchangeParticipant{Tenant: t.Scope.Tenant, Partner: t.Scope.Partner, Actor: t.Actor, AuthorityRevision: t.AuthorityRevision, RootPolicyDigest: secure.Digest([]byte(t.Root))}
}

func exchangeSender(d ExchangeEndpointDefinition, actor ExchangeParticipant) (ExchangeParticipant, error) {
	for _, sender := range d.Senders {
		if sender.Actor == actor.Actor {
			if sender != actor {
				return ExchangeParticipant{}, ErrNotFound
			}
			return sender, nil
		}
	}
	return ExchangeParticipant{}, ErrNotFound
}

func bindExchangeEndpoint(v *ExchangeEndpointVersion, ref ExchangeEndpointReference, limits ExchangeLimits) (*ExchangeEndpointDefinition, error) {
	if v == nil || v.State != "active" || v.ID != ref.ID || v.Revision != ref.Revision || v.Hash != ref.Hash {
		return nil, ErrRevision
	}
	d, _, hash, err := DecodeExchangeEndpoint(v.Definition, limits)
	if err != nil || hash != v.Hash {
		return nil, ErrIsolation
	}
	return d, nil
}

func (t *Transaction) ArtifactExchange(ctx context.Context, id string) (*ArtifactExchange, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	var e ArtifactExchange
	var wire string
	err := t.Tx.QueryRow(ctx, `SELECT exchange_id::text,sender_actor_id::text,recipient_actor_id::text,request_wire,request_hash,storage_id::text,event_id::text FROM artifact_exchanges WHERE exchange_id=$1`, id).Scan(&e.ID, &e.Sender, &e.Recipient, &wire, &e.RequestHash, &e.StorageID, &e.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(wire) > 16<<10 || secure.Digest([]byte(wire)) != e.RequestHash || json.Unmarshal([]byte(wire), &e.Request) != nil {
		return nil, ErrIsolation
	}
	return &e, nil
}

func (t *Transaction) ArtifactExchangeReplay(ctx context.Context, key, meaning string, limits ExchangeLimits) (*ArtifactExchange, error) {
	if !ValidBrowserOperationKey(key) || !browserSecretHash.MatchString(meaning) {
		return nil, ErrExchangeInput
	}
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":artifact-exchanges"); err != nil {
		return nil, err
	}
	var previous, id string
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,exchange_id::text FROM artifact_exchange_commands WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&previous, &id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if previous != meaning {
		return nil, ErrConflict
	}
	e, err := t.ArtifactExchange(ctx, id)
	if err != nil {
		return nil, err
	}
	// A historical receipt is no retrieval grant. Preserve the original result
	// after endpoint revocation/expiry, but never after sender authority changes.
	var wire string
	err = t.Tx.QueryRow(ctx, `SELECT definition_wire FROM exchange_endpoint_versions WHERE endpoint_id=$1 AND revision=$2 AND definition_hash=$3`, e.Request.Endpoint.ID, e.Request.Endpoint.Revision, e.Request.Endpoint.Hash).Scan(&wire)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d, _, _, err := DecodeExchangeEndpoint([]byte(wire), limits)
	if err != nil {
		return nil, ErrIsolation
	}
	if _, err = exchangeSender(*d, t.exchangeParticipant()); err != nil || e.Sender != t.Actor {
		return nil, ErrNotFound
	}
	if err = t.exchangeNamespaceReadLock(ctx); err != nil {
		return nil, err
	}
	var sourceAllowed bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_exchange_actor_source_readable($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, e.Request.Artifact.ID, t.Actor).Scan(&sourceAllowed); err != nil {
		return nil, err
	}
	if !sourceAllowed {
		return nil, ErrNotFound
	}
	return e, nil
}

// PrepareArtifactExchange runs under the sender's real authentication. The
// namespace lock holds source path/mode authority through publication of the
// new receive view; later reads recheck source access, the explicit view and
// current file policy without acting as the sender.
func (t *Transaction) PrepareArtifactExchange(ctx context.Context, r ExchangeRequest, limits ExchangeLimits, maximum int) (*ArtifactExchange, error) {
	if _, _, err := CanonicalExchangeRequest(r, limits); err != nil || maximum < 1 || maximum > 10000 {
		return nil, ErrExchangeInput
	}
	for _, permission := range []string{"read", "deliver"} {
		if err := t.Require(permission); err != nil {
			return nil, err
		}
	}
	v, err := t.CurrentExchangeEndpoint(ctx, r.Endpoint.ID)
	if err != nil {
		return nil, err
	}
	d, err := bindExchangeEndpoint(v, r.Endpoint, limits)
	if err != nil {
		return nil, err
	}
	sender, err := exchangeSender(*d, t.exchangeParticipant())
	if err != nil {
		return nil, err
	}
	if err = t.validateExchangeEndpointParticipants(ctx, ExchangeEndpointDefinition{Recipient: d.Recipient, Senders: []ExchangeParticipant{sender}}); err != nil {
		return nil, err
	}
	if err = t.exchangeNamespaceReadLock(ctx); err != nil {
		return nil, err
	}
	policy, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	if err = t.FileAccessible(ctx, r.Artifact.ID); err != nil {
		return nil, err
	}
	f, err := t.File(ctx, r.Artifact.ID)
	if err != nil {
		return nil, err
	}
	if r.Artifact != (ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}) {
		return nil, ErrRevision
	}
	if err = exchangePolicyCurrent(f, policy); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if err = r.ValidateAdmission(now, limits); err != nil {
		return nil, err
	}
	var count int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM artifact_exchanges WHERE sender_actor_id=$1 AND expires_at>clock_timestamp()`, t.Actor).Scan(&count); err != nil {
		return nil, err
	}
	if count >= maximum {
		return nil, ErrLimit
	}
	if r.ReplyTo != "" {
		prior, err := t.ArtifactExchange(ctx, r.ReplyTo)
		if err != nil || prior.Recipient != t.Actor || prior.Sender != d.Recipient.Actor {
			return nil, ErrNotFound
		}
	}
	r.ExpiresAt = r.ExpiresAt.UTC()
	_, hash, err := CanonicalExchangeRequest(r, limits)
	if err != nil {
		return nil, err
	}
	return &ArtifactExchange{ID: secure.NewID(), Sender: t.Actor, Recipient: d.Recipient.Actor, Request: r, RequestHash: hash}, nil
}

func (t *Transaction) SaveArtifactExchange(ctx context.Context, key string, e *ArtifactExchange) error {
	if e == nil || e.EventID != "" || !ValidID(e.StorageID) || !ValidBrowserOperationKey(key) {
		return ErrExchangeInput
	}
	wire, err := json.Marshal(e.Request)
	if err != nil || len(wire) > 16<<10 || secure.Digest(wire) != e.RequestHash {
		return ErrExchangeInput
	}
	if err = t.Reauthorize(ctx); err != nil {
		return err
	}
	e.EventID, err = t.Append(ctx, "ArtifactExchangeOffered", e.ID, map[string]any{"exchange": e, "storage_id": e.StorageID})
	if err != nil {
		return err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO artifact_exchanges(tenant_id,partner_id,exchange_id,sender_actor_id,recipient_actor_id,file_id,endpoint_id,endpoint_revision,request,request_wire,request_hash,storage_id,expires_at,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, t.Scope.Tenant, t.Scope.Partner, e.ID, e.Sender, e.Recipient, e.Request.Artifact.ID, e.Request.Endpoint.ID, e.Request.Endpoint.Revision, wire, string(wire), e.RequestHash, e.StorageID, e.Request.ExpiresAt, e.EventID); err != nil {
		return err
	}
	result := ArtifactExchangeResult{Exchange: *e}
	event, err := t.Append(ctx, "ArtifactExchangeCommandCompleted", e.ID, map[string]any{"request_key": key, "request_hash": e.RequestHash, "result": result})
	if err != nil {
		return err
	}
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO artifact_exchange_commands(tenant_id,partner_id,actor_id,request_key,request_hash,exchange_id,result,event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, e.RequestHash, e.ID, data, event)
	return err
}

// Resolve the immutable record internally. An untrusted caller cannot turn a
// hand-built record with a real endpoint into permission for an unoffered file.
func (t *Transaction) AuthorizeIncomingExchange(ctx context.Context, id string, limits ExchangeLimits) (*ArtifactExchange, *File, error) {
	e, err := t.ArtifactExchange(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	f, err := t.authorizeIncomingExchange(ctx, e, limits)
	if errors.Is(err, ErrState) {
		return e, nil, err
	}
	if err != nil {
		return nil, nil, err
	}
	return e, f, nil
}

func (t *Transaction) authorizeIncomingExchange(ctx context.Context, e *ArtifactExchange, limits ExchangeLimits) (*File, error) {
	if e == nil || e.Recipient != t.Actor {
		return nil, ErrNotFound
	}
	if err := t.Require("read"); err != nil {
		return nil, err
	}
	v, err := t.CurrentExchangeEndpoint(ctx, e.Request.Endpoint.ID)
	if err != nil {
		return nil, err
	}
	d, err := bindExchangeEndpoint(v, e.Request.Endpoint, limits)
	if err != nil {
		return nil, err
	}
	if d.Recipient != t.exchangeParticipant() {
		return nil, ErrNotFound
	}
	var sender *ExchangeParticipant
	for _, p := range d.Senders {
		if p.Actor == e.Sender {
			copy := p
			sender = &copy
		}
	}
	if sender == nil {
		return nil, ErrNotFound
	}
	if err = t.validateExchangeEndpointParticipants(ctx, ExchangeEndpointDefinition{Recipient: d.Recipient, Senders: []ExchangeParticipant{*sender}}); err != nil {
		return nil, err
	}
	if err = t.exchangeNamespaceReadLock(ctx); err != nil {
		return nil, err
	}
	// This checks a dependency of the stored grant. It does not authenticate or
	// act as its sender, and never changes this transaction's acting identity.
	var sourceAllowed bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_exchange_actor_source_readable($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, e.Request.Artifact.ID, e.Sender).Scan(&sourceAllowed); err != nil {
		return nil, err
	}
	if !sourceAllowed {
		return nil, ErrNotFound
	}
	policy, err := t.IntakePolicy(ctx, false)
	if err != nil {
		return nil, err
	}
	availabilityErr := t.FileAvailable(ctx, e.Request.Artifact.ID)
	if availabilityErr != nil && !errors.Is(availabilityErr, ErrState) {
		return nil, availabilityErr
	}
	f, err := t.File(ctx, e.Request.Artifact.ID)
	if err != nil {
		return nil, err
	}
	if e.Request.Artifact != (ExchangeArtifact{ID: f.ID, Size: f.Size, SHA256: f.SHA256, Policy: f.Policy}) {
		return nil, ErrIsolation
	}
	if err = exchangePolicyCurrent(f, policy); err != nil {
		availabilityErr = err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	// Recheck time-based expiry after lock waits and all other proof reads.
	var current, available bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_artifact_exchange_principals_current(e),freightctl_artifact_exchange_policy_current(e.tenant_id,e.partner_id,e.file_id) FROM artifact_exchanges e WHERE exchange_id=$1`, e.ID).Scan(&current, &available); err != nil {
		return nil, err
	}
	if !current {
		return nil, ErrNotFound
	}
	if !available || availabilityErr != nil {
		return nil, ErrState
	}
	return f, nil
}

func exchangePolicyCurrent(f *File, policy *Configuration) error {
	if f == nil || policy == nil && f.Policy != "integrity-only-v1" || policy != nil && (policy.State != "active" || f.Policy != "intake-csv-v1:"+policy.Hash) {
		return ErrState
	}
	return nil
}

func (t *Transaction) exchangeNamespaceReadLock(ctx context.Context) error {
	_, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":namespace-v1")
	return err
}

func (s *Store) IncomingExchanges(ctx context.Context, scope Scope, endpoint, after string, limit int, limits ExchangeLimits) (*ArtifactExchangePage, error) {
	if !ValidID(endpoint) || after != "" && !ValidID(after) || limit < 1 || limit > 100 || !limits.valid() {
		return nil, ErrExchangeInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	v, err := t.CurrentExchangeEndpoint(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	d, err := bindExchangeEndpoint(v, ExchangeEndpointReference{ID: v.ID, Revision: v.Revision, Hash: v.Hash}, limits)
	if err != nil {
		return nil, err
	}
	if d.Recipient != t.exchangeParticipant() || !t.Has("list") || !t.Has("read") {
		return nil, ErrNotFound
	}
	rows, err := t.Tx.Query(ctx, `SELECT exchange_id::text FROM artifact_exchanges e WHERE recipient_actor_id=$1 AND endpoint_id=$2 AND endpoint_revision=$3 AND freightctl_artifact_exchange_principals_current(e) AND ($4='' OR exchange_id>nullif($4,'')::uuid) ORDER BY exchange_id LIMIT $5`, t.Actor, endpoint, v.Revision, after, limit+1)
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
	page := &ArtifactExchangePage{Exchanges: make([]IncomingExchange, 0, limit)}
	if len(ids) > limit {
		page.Next = ids[limit-1]
		ids = ids[:limit]
	}
	for _, id := range ids {
		e, err := t.ArtifactExchange(ctx, id)
		if err != nil {
			return nil, err
		}
		// The query and live check both authorize metadata. Withheld bytes get
		// only an opaque view ID and fixed state, never artifact details. A race
		// that revokes a principal refuses the whole page, including its cursor.
		if _, err = t.authorizeIncomingExchange(ctx, e, limits); err != nil {
			if errors.Is(err, ErrState) {
				page.Exchanges = append(page.Exchanges, IncomingExchange{ID: e.ID, State: "held"})
				continue
			}
			return nil, err
		}
		page.Exchanges = append(page.Exchanges, IncomingExchange{ID: e.ID, State: "offered", Exchange: e})
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}
