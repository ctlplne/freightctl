package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type UploadSession struct {
	StorageID       string
	ID, Actor, Root string
	Authority       int64
	Target          json.RawMessage
	ExpectedSize    int64
	ExpectedSHA     string
	Offset          int64
	Chunks          int
	State, FileID   string
	Revision        int64
	EventID         string
	Modified        time.Time
}
type UploadChunk struct {
	Offset, Size              int64
	ObjectID, SHA256, EventID string
}

func (t *Transaction) OwnedUploadIDs(ctx context.Context, after string, limit int) ([]string, bool, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 101 {
		return nil, false, ErrNotFound
	}
	if err := t.Require("write"); err != nil {
		return nil, false, err
	}
	rows, err := t.Tx.Query(ctx, `SELECT upload_id::text FROM upload_sessions WHERE actor_id=$1 AND authority_revision=$2 AND namespace_root=$3 AND ($4::uuid IS NULL OR upload_id>$4::uuid) ORDER BY upload_id LIMIT $5`, t.Actor, t.AuthorityRevision, t.Root, nullableID(after), limit)
	if err != nil {
		return nil, false, err
	}
	ids := make([]string, 0, limit)
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, false, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	var blocked bool
	err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM upload_sessions WHERE actor_id=$1 AND state='open' AND (authority_revision<>$2 OR namespace_root<>$3))`, t.Actor, t.AuthorityRevision, t.Root).Scan(&blocked)
	return ids, blocked, err
}

func nullableID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func (t *Transaction) UploadLock(ctx context.Context, id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	_, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":upload:"+id)
	return err
}
func (t *Transaction) Upload(ctx context.Context, id string) (*UploadSession, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	u := &UploadSession{}
	err := t.Tx.QueryRow(ctx, `SELECT u.upload_id::text,u.actor_id::text,u.namespace_root,u.storage_id,u.authority_revision,u.target,u.expected_size,u.expected_sha256,u.committed_offset,u.chunk_count,u.state,coalesce(u.file_id::text,''),u.revision,u.changed_event_id::text,e.happened_at FROM upload_sessions u JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(u.tenant_id,u.partner_id,u.changed_event_id) WHERE u.upload_id=$1 AND u.actor_id=$2`, id, t.Actor).Scan(&u.ID, &u.Actor, &u.Root, &u.StorageID, &u.Authority, &u.Target, &u.ExpectedSize, &u.ExpectedSHA, &u.Offset, &u.Chunks, &u.State, &u.FileID, &u.Revision, &u.EventID, &u.Modified)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if u.Root != t.Root || u.Authority != t.AuthorityRevision {
		return nil, ErrUnauthorized
	}
	if err = t.Require("write"); err != nil {
		return nil, err
	}
	return u, nil
}
func (t *Transaction) SaveUpload(ctx context.Context, old, u *UploadSession, kind string, chunk *UploadChunk) error {
	p := map[string]any{"namespace_root": u.Root, "storage_id": u.StorageID, "authority_revision": u.Authority, "target": u.Target, "expected_size": u.ExpectedSize, "expected_sha256": u.ExpectedSHA, "committed_offset": u.Offset, "chunk_count": u.Chunks, "state": u.State, "file_id": u.FileID, "revision": u.Revision, "protocol_session_id": t.Scope.SessionID}
	if chunk != nil {
		p["chunk_object_id"] = chunk.ObjectID
		p["chunk_offset"] = chunk.Offset
		p["chunk_size"] = chunk.Size
		p["chunk_sha256"] = chunk.SHA256
	}
	event, err := t.Append(ctx, kind, u.ID, p)
	if err != nil {
		return err
	}
	u.EventID = event
	if old == nil {
		_, err = t.Tx.Exec(ctx, `INSERT INTO upload_sessions(tenant_id,partner_id,upload_id,actor_id,namespace_root,authority_revision,target,expected_size,expected_sha256,committed_offset,chunk_count,state,file_id,revision,changed_event_id,storage_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,nullif($13,'')::uuid,$14,$15,$16)`, t.Scope.Tenant, t.Scope.Partner, u.ID, u.Actor, u.Root, u.Authority, u.Target, u.ExpectedSize, u.ExpectedSHA, u.Offset, u.Chunks, u.State, u.FileID, u.Revision, event, u.StorageID)
	} else {
		var tag pgconn.CommandTag
		tag, err = t.Tx.Exec(ctx, `UPDATE upload_sessions SET committed_offset=$1,chunk_count=$2,state=$3,file_id=nullif($4,'')::uuid,revision=$5,changed_event_id=$6 WHERE upload_id=$7 AND actor_id=$8 AND revision=$9`, u.Offset, u.Chunks, u.State, u.FileID, u.Revision, event, u.ID, t.Actor, old.Revision)
		if err == nil && tag.RowsAffected() != 1 {
			err = ErrRevision
		}
	}
	if err != nil {
		return err
	}
	if chunk != nil {
		chunk.EventID = event
		_, err = t.Tx.Exec(ctx, `INSERT INTO upload_chunks VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Scope.Tenant, t.Scope.Partner, u.ID, t.Actor, chunk.Offset, chunk.ObjectID, chunk.Size, chunk.SHA256, event)
	}
	if err != nil {
		return err
	}
	return t.Tx.QueryRow(ctx, `SELECT happened_at FROM events WHERE event_id=$1`, event).Scan(&u.Modified)
}
func (t *Transaction) UploadChunks(ctx context.Context, id string) ([]UploadChunk, error) {
	rows, err := t.Tx.Query(ctx, `SELECT start_offset,object_id::text,size_bytes,sha256,checkpoint_event_id::text FROM upload_chunks WHERE upload_id=$1 AND actor_id=$2 ORDER BY start_offset LIMIT 4097`, id, t.Actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	chunks := make([]UploadChunk, 0)
	for rows.Next() {
		var c UploadChunk
		if err = rows.Scan(&c.Offset, &c.ObjectID, &c.Size, &c.SHA256, &c.EventID); err != nil {
			return nil, err
		}
		chunks = append(chunks, c)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(chunks) > 4096 {
		return nil, ErrLimit
	}
	return chunks, nil
}
func (t *Transaction) ReplayUpload(ctx context.Context, key, meaning string) (json.RawMessage, error) {
	if !operationKey.MatchString(key) {
		return nil, ErrState
	}
	_, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":"+t.Actor+":upload-key:"+key)
	if err != nil {
		return nil, err
	}
	var hash string
	var result json.RawMessage
	err = t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM upload_receipts WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&hash, &result)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if hash != meaning {
		return nil, ErrConflict
	}
	return result, nil
}
func (t *Transaction) SaveUploadReceipt(ctx context.Context, key, meaning, id string, result any) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if len(data) > 16<<10 {
		return ErrLimit
	}
	event, err := t.Append(ctx, "UploadCommandCompleted", id, map[string]any{"request_key": key, "request_hash": meaning, "result": result, "protocol_session_id": t.Scope.SessionID})
	if err != nil {
		return err
	}
	_, err = t.Tx.Exec(ctx, `INSERT INTO upload_receipts VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, id, data, event)
	return err
}
func UploadMeaning(value any) string { data, _ := json.Marshal(value); return secure.Digest(data) }
