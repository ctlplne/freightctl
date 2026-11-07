package store

import (
	"context"
	"errors"
	"regexp"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

var browserOperationKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var browserSecretHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidBrowserOperationKey(key string) bool { return browserOperationKey.MatchString(key) }

type BrowserSession struct {
	CredentialHash  string    `json:"credential_sha256"`
	ID              string    `json:"id"`
	SecretHash      string    `json:"secret_sha256"`
	RequestKey      string    `json:"request_key"`
	Root            string    `json:"namespace_root"`
	Authority       int64     `json:"authority_revision"`
	LifetimeSeconds int       `json:"lifetime_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`
	State           string    `json:"state"`
	Revision        int64     `json:"revision"`
	Replayed        bool      `json:"-"`
}

func (t *Transaction) currentBrowserSession(ctx context.Context) error {
	if !ValidID(t.Scope.BrowserSessionID) || !browserSecretHash.MatchString(t.Scope.BrowserSessionHash) || t.Scope.SessionID != t.Scope.BrowserSessionID || t.Scope.AuthorityRevision < 1 || t.Scope.TokenHash == "" {
		return ErrUnauthorized
	}
	var id string
	query := `SELECT session_id::text FROM browser_sessions WHERE session_id=$1 AND secret_hash=$2 AND actor_id=$3 AND namespace_root=$4 AND authority_revision=$5 AND state='active' AND expires_at>clock_timestamp() AND credential_hash=$6`
	if t.lockedBrowserSession != t.Scope.BrowserSessionID {
		query += ` FOR SHARE`
	}
	err := t.Tx.QueryRow(ctx, query, t.Scope.BrowserSessionID, t.Scope.BrowserSessionHash, t.Actor, t.Root, t.AuthorityRevision, t.Scope.TokenHash).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err == nil {
		// Repeated checks still query every live predicate. They reuse only the
		// transaction's existing row lock,not a cached authorization decision.
		t.lockedBrowserSession = id
	}
	return err
}

func (s *Store) CreateBrowserSession(ctx context.Context, scope Scope, key, hash string, lifetime time.Duration) (*BrowserSession, *Identity, time.Time, error) {
	if lifetime < time.Second || lifetime > 10*time.Minute || lifetime%time.Second != 0 || !ValidBrowserOperationKey(key) || !browserSecretHash.MatchString(hash) || scope.TokenHash == "" || scope.BrowserSessionID != "" || scope.BrowserSessionHash != "" {
		return nil, nil, time.Time{}, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	defer t.Tx.Rollback(ctx)
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+t.Actor+":browser-sessions"); err != nil {
		return nil, nil, time.Time{}, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, nil, now, err
	}
	b := &BrowserSession{}
	err = t.Tx.QueryRow(ctx, `SELECT session_id::text,secret_hash,credential_hash,request_key,namespace_root,authority_revision,lifetime_seconds,expires_at,state,revision FROM browser_sessions WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&b.ID, &b.SecretHash, &b.CredentialHash, &b.RequestKey, &b.Root, &b.Authority, &b.LifetimeSeconds, &b.ExpiresAt, &b.State, &b.Revision)
	if err == nil {
		if b.SecretHash != hash || b.CredentialHash != scope.TokenHash || b.Root != t.Root || b.Authority != t.AuthorityRevision || b.LifetimeSeconds != int(lifetime/time.Second) {
			return nil, nil, now, ErrConflict
		}
		b.Replayed = true
		who, err := transactionIdentity(ctx, t)
		if err != nil {
			return nil, nil, now, err
		}
		return b, who, now, t.Tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, now, err
	}
	var active int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM browser_sessions WHERE actor_id=$1 AND state='active' AND expires_at>clock_timestamp()`, t.Actor).Scan(&active); err != nil {
		return nil, nil, now, err
	}
	if active >= 8 {
		return nil, nil, now, ErrLimit
	}
	b = &BrowserSession{ID: secure.NewID(), SecretHash: hash, CredentialHash: scope.TokenHash, RequestKey: key, Root: t.Root, Authority: t.AuthorityRevision, LifetimeSeconds: int(lifetime / time.Second), ExpiresAt: now.UTC().Add(lifetime), State: "active", Revision: 1}
	if t.ExpiresAt != nil && b.ExpiresAt.After(*t.ExpiresAt) {
		b.ExpiresAt = *t.ExpiresAt
	}
	event, err := t.Append(ctx, "BrowserSessionChanged", b.ID, b)
	if err != nil {
		return nil, nil, now, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO browser_sessions(tenant_id,partner_id,actor_id,session_id,secret_hash,credential_hash,request_key,namespace_root,authority_revision,lifetime_seconds,expires_at,state,revision,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, scope.Tenant, scope.Partner, t.Actor, b.ID, b.SecretHash, b.CredentialHash, b.RequestKey, b.Root, b.Authority, b.LifetimeSeconds, b.ExpiresAt, b.State, b.Revision, event); err != nil {
		return nil, nil, now, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, nil, now, err
	}
	who, err := transactionIdentity(ctx, t)
	if err != nil {
		return nil, nil, now, err
	}
	return b, who, now, t.Tx.Commit(ctx)
}

// BrowserScope only resolves an opaque credential into ordinary scoped proof.
// Every later service transaction rechecks both the parent credential and this
// session's live state/expiry. No plaintext browser secret is stored in SQL.
func (s *Store) BrowserScope(ctx context.Context, tenant, partner, hash string) (Scope, *BrowserSession, error) {
	if !browserSecretHash.MatchString(hash) {
		return Scope{}, nil, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	scope := Scope{Tenant: tenant, Partner: partner, BrowserSessionHash: hash}
	tx, err := s.scopedTransaction(ctx, scope, pgx.TxOptions{})
	if err != nil {
		return Scope{}, nil, err
	}
	defer tx.Rollback(ctx)
	b := &BrowserSession{}
	err = tx.QueryRow(ctx, `SELECT b.session_id::text,b.secret_hash,b.credential_hash,b.request_key,b.namespace_root,b.authority_revision,b.lifetime_seconds,b.expires_at,b.state,b.revision,c.token_hash FROM browser_sessions b JOIN credentials c USING(tenant_id,partner_id,actor_id) WHERE b.secret_hash=$1 AND b.state='active' AND b.expires_at>clock_timestamp() AND c.revoked_at IS NULL AND (c.expires_at IS NULL OR c.expires_at>clock_timestamp()) AND c.token_hash=b.credential_hash AND (c.namespace_root,c.authority_revision)=(b.namespace_root,b.authority_revision)`, hash).Scan(&b.ID, &b.SecretHash, &b.CredentialHash, &b.RequestKey, &b.Root, &b.Authority, &b.LifetimeSeconds, &b.ExpiresAt, &b.State, &b.Revision, &scope.TokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scope{}, nil, ErrUnauthorized
	}
	if err != nil {
		return Scope{}, nil, err
	}
	scope.BrowserSessionID = b.ID
	scope.SessionID = b.ID
	scope.AuthorityRevision = b.Authority
	return scope, b, tx.Commit(ctx)
}

// RevokeBrowserSession is a close-only capability. Even an expired/revoked
// browser secret can acknowledge its original logout without recovering general
// file authority. Its verified hash selects exactly one session; this function
// never returns the derived actor context to ordinary services.
func (s *Store) RevokeBrowserSession(ctx context.Context, scope Scope, key string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !browserSecretHash.MatchString(scope.BrowserSessionHash) || !ValidBrowserOperationKey(key) {
		return ErrUnauthorized
	}
	tx, err := s.scopedTransaction(ctx, scope, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var actor, id string
	err = tx.QueryRow(ctx, `SELECT actor_id::text,session_id::text FROM browser_sessions WHERE secret_hash=$1`, scope.BrowserSessionHash).Scan(&actor, &id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return err
	}
	if scope.BrowserSessionID != "" && scope.BrowserSessionID != id {
		return ErrUnauthorized
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.actor_id',$1,true)`, actor); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":"+actor+":browser-command:"+key); err != nil {
		return err
	}
	meaning := secure.Digest([]byte("browser.logout.v1\x00" + id))
	var previous string
	err = tx.QueryRow(ctx, `SELECT request_hash FROM browser_commands WHERE request_key=$1`, key).Scan(&previous)
	if err == nil {
		if previous != meaning {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	b := &BrowserSession{}
	err = tx.QueryRow(ctx, `SELECT session_id::text,secret_hash,credential_hash,request_key,namespace_root,authority_revision,lifetime_seconds,expires_at,state,revision FROM browser_sessions WHERE session_id=$1 AND actor_id=$2 FOR UPDATE`, id, actor).Scan(&b.ID, &b.SecretHash, &b.CredentialHash, &b.RequestKey, &b.Root, &b.Authority, &b.LifetimeSeconds, &b.ExpiresAt, &b.State, &b.Revision)
	if err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM browser_commands WHERE session_id=$1`, id).Scan(&count); err != nil {
		return err
	}
	if count >= 16 {
		return ErrLimit
	}
	scope.SessionID = id
	t := &Transaction{Tx: tx, Scope: scope, Actor: actor, Root: b.Root, AuthorityRevision: b.Authority}
	if b.State == "active" {
		b.State = "revoked"
		b.Revision++
		if t.ExpiresAt != nil && b.ExpiresAt.After(*t.ExpiresAt) {
			b.ExpiresAt = *t.ExpiresAt
		}
		event, err := t.Append(ctx, "BrowserSessionChanged", b.ID, b)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE browser_sessions SET state=$1,revision=$2,changed_event_id=$3 WHERE session_id=$4 AND actor_id=$5`, b.State, b.Revision, event, b.ID, actor); err != nil {
			return err
		}
	}
	event, err := t.Append(ctx, "BrowserLogoutRecorded", id, map[string]any{"session_id": id, "request_key": key, "request_hash": meaning})
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO browser_commands(tenant_id,partner_id,actor_id,request_key,request_hash,session_id,event_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, scope.Tenant, scope.Partner, actor, key, meaning, id, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
