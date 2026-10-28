package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

var ErrUnauthorized = errors.New("unauthorized")
var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("idempotency key has different meaning")

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func ValidID(id string) bool { return uuidPattern.MatchString(id) }

// Scope comes from a verified credential; the transaction authenticates its requested scope first.
type Scope struct{ Tenant, Partner, TokenHash string }
type Store struct{ Pool *pgxpool.Pool }
type File struct {
	ID      string `json:"id"`
	Size    int64  `json:"size_bytes"`
	SHA256  string `json:"sha256"`
	Policy  string `json:"policy"`
	EventID string `json:"accepted_event_id"`
}
type Event struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	ResourceID string          `json:"resource_id"`
	Payload    json.RawMessage `json:"payload"`
	At         time.Time       `json:"happened_at"`
}
type Transaction struct {
	Tx    pgx.Tx
	Scope Scope
	Actor string
}

// Connection strings are read from bounded protected references. pgx requires a string copy.
func connect(ctx context.Context, path string) (*pgxpool.Pool, error) {
	secret, err := secure.ReadSecret(path, 4096)
	if err != nil {
		return nil, err
	}
	defer secret.Close()
	cfg, err := pgxpool.ParseConfig(string(secret.Bytes))
	if err != nil {
		return nil, errors.New("invalid database reference")
	}
	cfg.MaxConns = 8
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.ConnConfig.RuntimeParams["application_name"] = "freightctl"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "120000"
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("database unavailable")
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, errors.New("database unavailable")
	}
	return p, nil
}
func Open(ctx context.Context, path string) (*Store, error) {
	p, err := connect(ctx, path)
	if err != nil {
		return nil, err
	}
	var unsafe bool
	err = p.QueryRow(ctx, `SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=r.oid) OR EXISTS (SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace AND relowner=r.oid) FROM pg_roles r WHERE rolname=current_user`).Scan(&unsafe)
	if err != nil || unsafe {
		p.Close()
		return nil, errors.New("runtime database role must be non-owner without elevated privileges or memberships")
	}
	var version int
	err = p.QueryRow(ctx, `SELECT version FROM freightctl_schema WHERE version=1`).Scan(&version)
	if err != nil {
		p.Close()
		return nil, errors.New("database schema not initialized")
	}
	return &Store{Pool: p}, nil
}

// Migrate is an explicit administrative operation, never run with runtime credentials.
func Migrate(ctx context.Context, adminPath, passwordPath string) error {
	p, err := connect(ctx, adminPath)
	if err != nil {
		return err
	}
	defer p.Close()
	password, err := secure.ReadSecret(passwordPath, 256)
	if err != nil {
		return err
	}
	defer password.Close()
	if len(password.Bytes) < 32 {
		return errors.New("runtime password must contain at least 32 bytes")
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815033)`); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='freightctl_runtime')`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		// PostgreSQL utility statements cannot bind a password parameter; quote as SQL literal.
		_, err = tx.Exec(ctx, `CREATE ROLE freightctl_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '`+strings.ReplaceAll(string(password.Bytes), "'", "''")+`'`)
		if err != nil {
			return errors.New("cannot create runtime role")
		}
	}
	if _, err = tx.Exec(ctx, `REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE TABLE IF NOT EXISTS freightctl_schema(version integer PRIMARY KEY, digest text NOT NULL); GRANT SELECT ON freightctl_schema TO freightctl_runtime`); err != nil {
		return err
	}
	var digest string
	err = tx.QueryRow(ctx, `SELECT digest FROM freightctl_schema WHERE version=1`).Scan(&digest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err = tx.Exec(ctx, schema); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO freightctl_schema VALUES(1,$1)`, secure.Digest([]byte(schema))); err != nil {
			return err
		}
	case err != nil:
		return err
	case digest != secure.Digest([]byte(schema)):
		return errors.New("existing migration digest differs; do not rewrite applied migrations")
	}
	return tx.Commit(ctx)
}

func Provision(ctx context.Context, adminPath, tenant, partner, tokenPath string) error {
	if !ValidID(tenant) || !ValidID(partner) {
		return errors.New("invalid tenant or partner UUID")
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		return err
	}
	defer secret.Close()
	if len(secret.Bytes) != 64 {
		return errors.New("token must be 64 bytes")
	}
	p, err := connect(ctx, adminPath)
	if err != nil {
		return err
	}
	defer p.Close()
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true)`, tenant, partner)
	if err != nil {
		return err
	}
	actor := secure.NewID()
	if _, err = tx.Exec(ctx, `INSERT INTO tenants VALUES($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO partners VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, partner); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO credentials(tenant_id,partner_id,actor_id,token_hash) VALUES($1,$2,$3,$4)`, tenant, partner, actor, secure.Digest(secret.Bytes)); err != nil {
		return errors.New("cannot enroll duplicate or invalid identity")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,'ServiceIdentityEnrolled',$4,'{}')`, tenant, partner, secure.NewID(), actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Begin(ctx context.Context, scope Scope) (*Transaction, error) {
	if !ValidID(scope.Tenant) || !ValidID(scope.Partner) {
		return nil, ErrUnauthorized
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback(ctx)
		}
	}()
	_, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true)`, scope.Tenant, scope.Partner)
	if err != nil {
		return nil, err
	}
	var actor string
	err = tx.QueryRow(ctx, `SELECT actor_id::text FROM credentials WHERE token_hash=$1 AND revoked_at IS NULL`, scope.TokenHash).Scan(&actor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return &Transaction{Tx: tx, Scope: scope, Actor: actor}, nil
}
func (t *Transaction) Replay(ctx context.Context, key, meaning string) (*File, error) {
	// Database ownership serializes concurrent uploads, including different service processes.
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+key); err != nil {
		return nil, err
	}
	var prior, id string
	err := t.Tx.QueryRow(ctx, `SELECT request_hash,file_id::text FROM idempotency WHERE request_key=$1`, key).Scan(&prior, &id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if prior != meaning {
		return nil, ErrConflict
	}
	return t.File(ctx, id)
}
func (t *Transaction) File(ctx context.Context, id string) (*File, error) {
	f := &File{}
	err := t.Tx.QueryRow(ctx, `SELECT file_id::text,size_bytes,sha256,policy,accepted_event_id::text FROM files WHERE file_id=$1`, id).Scan(&f.ID, &f.Size, &f.SHA256, &f.Policy, &f.EventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return f, err
}
func (t *Transaction) Append(ctx context.Context, kind, resource string, payload any) (string, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	id := secure.NewID()
	_, err = t.Tx.Exec(ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, id, t.Actor, kind, resource, b)
	return id, err
}
func (t *Transaction) Accept(ctx context.Context, key, meaning string, f *File) error {
	if err := t.Reauthorize(ctx); err != nil {
		return err
	}
	id, err := t.Append(ctx, "FileAccepted", f.ID, map[string]any{"size_bytes": f.Size, "sha256": f.SHA256, "policy": f.Policy})
	if err != nil {
		return err
	}
	f.EventID = id
	_, err = t.Tx.Exec(ctx, `INSERT INTO files VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, f.ID, f.Size, f.SHA256, f.Policy, f.EventID)
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO idempotency VALUES($1,$2,$3,$4,$5)`, t.Scope.Tenant, t.Scope.Partner, key, meaning, f.ID)
	return err
}
func (t *Transaction) Reauthorize(ctx context.Context) error {
	var allowed bool
	err := t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM credentials WHERE actor_id=$1 AND token_hash=$2 AND revoked_at IS NULL)`, t.Actor, t.Scope.TokenHash).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrUnauthorized
	}
	return nil
}
func (s *Store) Events(ctx context.Context, scope Scope) ([]Event, error) {
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	rows, err := t.Tx.Query(ctx, `SELECT event_id::text,kind,resource_id::text,payload,happened_at FROM events ORDER BY happened_at DESC,event_id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	result := make([]Event, 0)
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.Kind, &e.ResourceID, &e.Payload, &e.At); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, e)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return result, t.Tx.Commit(ctx)
}
func Meaning(size int64, digest string) string {
	return secure.Digest([]byte(fmt.Sprintf("integrity-only-v1:%d:%s", size, digest)))
}
