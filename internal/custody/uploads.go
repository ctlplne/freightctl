package custody

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

const MaxUploadChunk int64 = 8 << 20
const MinUploadChunk int64 = 64 << 10

type CreateUpload struct {
	Path             string     `json:"path"`
	Size             int64      `json:"expected_size"`
	SHA256           string     `json:"expected_sha256"`
	ExpectedRevision *int64     `json:"expected_revision,omitempty"`
	Mode             *uint32    `json:"mode,omitempty"`
	Modified         *time.Time `json:"modified_at,omitempty"`
}
type UploadView struct {
	ID             string    `json:"id"`
	Path           string    `json:"path"`
	SFTPPath       string    `json:"sftp_path"`
	FTPSPath       string    `json:"ftps_path,omitempty"`
	ExpectedSize   int64     `json:"expected_size"`
	ExpectedSHA256 string    `json:"expected_sha256"`
	Offset         int64     `json:"committed_offset"`
	Chunks         int       `json:"chunk_count"`
	State          string    `json:"state"`
	Revision       int64     `json:"revision"`
	Modified       time.Time `json:"modified_at"`
	EventID        string    `json:"changed_event_id"`
	FileID         string    `json:"file_id,omitempty"`
	Acceptance     string    `json:"acceptance,omitempty"`
}
type UploadResult struct {
	Upload     UploadView  `json:"upload"`
	File       *store.File `json:"file,omitempty"`
	Replayed   bool        `json:"replayed"`
	Acceptance string      `json:"acceptance,omitempty"`
}

type UploadPage struct {
	Uploads               []UploadView `json:"uploads"`
	Next                  string       `json:"next,omitempty"`
	BlockedByAccessChange bool         `json:"blocked_by_access_change"`
}

func (s *Service) ListUploads(ctx context.Context, scope store.Scope, after string, limit int) (*UploadPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	ids, blocked, err := t.OwnedUploadIDs(ctx, after, limit+1)
	if err != nil {
		return nil, err
	}
	page := &UploadPage{Uploads: make([]UploadView, 0, min(limit, len(ids))), BlockedByAccessChange: blocked}
	if len(ids) > limit {
		page.Next = ids[limit-1]
		ids = ids[:limit]
	}
	for _, id := range ids {
		u, err := t.Upload(ctx, id)
		if err != nil {
			return nil, err
		}
		if err = s.checkUploadStorage(u); err != nil {
			return nil, err
		}
		view, err := uploadViewWithAcceptance(ctx, t, u)
		if err != nil {
			return nil, err
		}
		page.Uploads = append(page.Uploads, view)
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return page, t.Tx.Commit(ctx)
}

type uploadTarget struct {
	UploadTarget
	ParentID       string
	ParentRevision int64
}

func (s *Service) prepareUploadTarget(ctx context.Context, t *store.Transaction, u *store.UploadSession) (UploadTarget, error) {
	var target uploadTarget
	if err := json.Unmarshal(u.Target, &target); err != nil {
		return UploadTarget{}, store.ErrState
	}
	actual, err := prepareTarget(ctx, t, &target.UploadTarget)
	if err != nil {
		return UploadTarget{}, err
	}
	parent, err := t.Entry(ctx, vpath.Parent(actual))
	if err != nil {
		return UploadTarget{}, err
	}
	if parent.ID != target.ParentID || parent.Revision != target.ParentRevision {
		return UploadTarget{}, store.ErrRevision
	}
	return target.UploadTarget, nil
}

// WritableUploadStatus rechecks the current destination before a protocol
// accepts more bytes. Ordinary status remains an owned historical read.
func (s *Service) WritableUploadStatus(ctx context.Context, scope store.Scope, id string) (*UploadView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	u, err := t.Upload(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	if u.State != "open" {
		return nil, store.ErrState
	}
	if _, err = s.prepareUploadTarget(ctx, t, u); err != nil {
		return nil, err
	}
	view, err := uploadView(u)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &view, nil
}

func uploadView(u *store.UploadSession) (UploadView, error) {
	var target UploadTarget
	if err := json.Unmarshal(u.Target, &target); err != nil {
		return UploadView{}, store.ErrState
	}
	return UploadView{ID: u.ID, Path: target.Path, SFTPPath: "/.freightctl/uploads/" + u.ID, FTPSPath: "/.freightctl/uploads/" + u.ID, ExpectedSize: u.ExpectedSize, ExpectedSHA256: u.ExpectedSHA, Offset: u.Offset, Chunks: u.Chunks, State: u.State, Revision: u.Revision, Modified: u.Modified, EventID: u.EventID, FileID: u.FileID}, nil
}

func uploadViewWithAcceptance(ctx context.Context, t *store.Transaction, u *store.UploadSession) (UploadView, error) {
	view, err := uploadView(u)
	if err != nil {
		return view, err
	}
	if u.FileID != "" {
		file, err := t.File(ctx, u.FileID)
		if err != nil {
			return view, err
		}
		view.Acceptance = Acceptance(file)
	}
	return view, nil
}
func finishUpload(ctx context.Context, t *store.Transaction, key, meaning string, u *store.UploadSession, file *store.File) (*UploadResult, error) {
	view, err := uploadView(u)
	if err != nil {
		return nil, err
	}
	result := &UploadResult{Upload: view, File: file}
	if file != nil {
		result.Acceptance = Acceptance(file)
		result.Upload.Acceptance = result.Acceptance
	}
	if err = t.SaveUploadReceipt(ctx, key, meaning, u.ID, result); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
func replayUpload(ctx context.Context, t *store.Transaction, key, meaning, storageID string) (*UploadResult, error) {
	data, err := t.ReplayUpload(ctx, key, meaning)
	if err != nil || data == nil {
		return nil, err
	}
	result := &UploadResult{}
	if err = json.Unmarshal(data, result); err != nil {
		return nil, err
	}
	u, err := t.Upload(ctx, result.Upload.ID)
	if err != nil {
		return nil, err
	}
	if storageID != "" && u.StorageID != storageID {
		return nil, ErrStorageIdentity
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	result.Replayed = true
	return result, nil
}
func (s *Service) CreateUpload(ctx context.Context, scope store.Scope, key string, input CreateUpload) (*UploadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if s.Disk == nil {
		return nil, ErrStorageIdentity
	}
	if err := s.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	canonical, err := vpath.Canonical(input.Path)
	if err != nil || canonical == "/" || vpath.ControlPath(canonical) {
		return nil, vpath.ErrPath
	}
	input.Path = canonical
	if input.Size < 0 || input.Size > s.MaxFile || !digestPattern.MatchString(input.SHA256) || input.Mode != nil && *input.Mode > 0777 {
		return nil, ErrInput
	}
	if input.Modified != nil {
		value := input.Modified.UTC().Truncate(time.Microsecond)
		input.Modified = &value
	}
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("write"); err != nil {
		return nil, err
	}
	meaning := store.UploadMeaning(struct {
		Operation, Root string
		Authority       int64
		Input           CreateUpload
	}{"create", t.Root, t.AuthorityRevision, input})
	result, err := replayUpload(ctx, t, key, meaning, s.Disk.Identity())
	if err != nil || result != nil {
		return result, err
	}
	target := UploadTarget{Path: input.Path, ExpectedRevision: input.ExpectedRevision, Mode: input.Mode, Modified: input.Modified}
	actual, err := prepareTarget(ctx, t, &target)
	if err != nil {
		return nil, err
	}
	parent, err := t.Entry(ctx, vpath.Parent(actual))
	if err != nil {
		return nil, err
	}
	var count int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM upload_sessions WHERE actor_id=$1 AND state='open'`, t.Actor).Scan(&count); err != nil {
		return nil, err
	}
	if count >= 128 {
		return nil, store.ErrLimit
	}
	encoded, err := json.Marshal(uploadTarget{UploadTarget: target, ParentID: parent.ID, ParentRevision: parent.Revision})
	if err != nil {
		return nil, err
	}
	u := &store.UploadSession{ID: secure.NewID(), StorageID: s.Disk.Identity(), Actor: t.Actor, Root: t.Root, Authority: t.AuthorityRevision, Target: encoded, ExpectedSize: input.Size, ExpectedSHA: input.SHA256, State: "open", Revision: 1}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.SaveUpload(ctx, nil, u, "UploadSessionCreated", nil); err != nil {
		return nil, err
	}
	return finishUpload(ctx, t, key, meaning, u, nil)
}
func (s *Service) UploadStatus(ctx context.Context, scope store.Scope, id string) (*UploadView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	u, err := t.Upload(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	view, err := uploadViewWithAcceptance(ctx, t, u)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &view, nil
}
func (s *Service) AppendUpload(ctx context.Context, scope store.Scope, id, key string, offset, size int64, digest string, body io.Reader) (*UploadResult, error) {
	return s.appendUpload(ctx, scope, id, key, offset, size, digest, body, false)
}

// TUS recovers progress with HEAD. Its offset precondition must hold under the
// same lock as acceptance,even when an ordinary idempotency receipt exists.
func (s *Service) AppendUploadAtCurrentOffset(ctx context.Context, scope store.Scope, id, key string, offset, size int64, digest string, body io.Reader) (*UploadResult, error) {
	return s.appendUpload(ctx, scope, id, key, offset, size, digest, body, true)
}

func (s *Service) appendUpload(ctx context.Context, scope store.Scope, id, key string, offset, size int64, digest string, body io.Reader, strictOffset bool) (*UploadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if offset < 0 || size < 1 || size > MaxUploadChunk || !digestPattern.MatchString(digest) {
		return nil, ErrInput
	}
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.UploadLock(ctx, id); err != nil {
		return nil, err
	}
	u, err := t.Upload(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	if strictOffset && offset != u.Offset {
		return nil, store.ErrRevision
	}
	meaning := store.UploadMeaning(struct {
		Operation, ID string
		Offset, Size  int64
		SHA           string
	}{"append", id, offset, size, digest})
	result, err := replayUpload(ctx, t, key, meaning, s.Disk.Identity())
	if err != nil || result != nil {
		return result, err
	}
	if u.State != "open" {
		return nil, store.ErrState
	}
	if u.ExpectedSize > s.MaxFile {
		return nil, ErrCapacity
	}
	if offset != u.Offset {
		return nil, store.ErrRevision
	}
	if size > u.ExpectedSize-offset || size < MinUploadChunk && offset+size != u.ExpectedSize {
		return nil, ErrInput
	}
	if u.Chunks >= 4096 {
		return nil, store.ErrLimit
	}
	if _, err = s.prepareUploadTarget(ctx, t, u); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	if err = s.Disk.Capacity(size, s.MaxStored); err != nil {
		return nil, err
	}
	chunk := &store.UploadChunk{Offset: offset, Size: size, SHA256: digest, ObjectID: secure.NewID()}
	if err = s.Disk.Stage(Name(scope.Tenant, scope.Partner, chunk.ObjectID), contextReader{ctx: ctx, reader: body}, size, digest); err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	// A stale process can leave a new orphan, never change an already recorded chunk.
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	next := *u
	next.Offset += size
	next.Chunks++
	next.Revision++
	if err = t.SaveUpload(ctx, u, &next, "UploadCheckpointed", chunk); err != nil {
		return nil, err
	}
	return finishUpload(ctx, t, key, meaning, &next, nil)
}
func (s *Service) AbortUpload(ctx context.Context, scope store.Scope, id, key string) (*UploadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.UploadLock(ctx, id); err != nil {
		return nil, err
	}
	u, err := t.Upload(ctx, id)
	if err != nil {
		return nil, err
	}
	meaning := store.UploadMeaning(struct{ Operation, ID string }{"abort", id})
	result, err := replayUpload(ctx, t, key, meaning, "")
	if err != nil || result != nil {
		return result, err
	}
	if u.State == "completed" {
		return nil, store.ErrState
	}
	if u.State == "aborted" {
		return finishUpload(ctx, t, key, meaning, u, nil)
	}
	if u.State != "open" {
		return nil, store.ErrState
	}
	next := *u
	next.State = "aborted"
	next.Revision++
	if err = t.SaveUpload(ctx, u, &next, "UploadAborted", nil); err != nil {
		return nil, err
	}
	return finishUpload(ctx, t, key, meaning, &next, nil)
}
func (s *Service) CompleteUpload(ctx context.Context, scope store.Scope, id, key string) (*UploadResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.UploadLock(ctx, id); err != nil {
		return nil, err
	}
	u, err := t.Upload(ctx, id)
	if err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	meaning := store.UploadMeaning(struct{ Operation, ID string }{"complete", id})
	result, err := replayUpload(ctx, t, key, meaning, s.Disk.Identity())
	if err != nil {
		return nil, err
	}
	if result != nil {
		if result.Upload.State == "rejected" {
			return result, ErrIntegrity
		}
		return result, nil
	}
	if u.State == "completed" {
		file, err := t.File(ctx, u.FileID)
		if err != nil {
			return nil, err
		}
		return finishUpload(ctx, t, key, meaning, u, file)
	}
	if u.State != "open" {
		return nil, store.ErrState
	}
	if u.Offset != u.ExpectedSize {
		return nil, store.ErrRevision
	}
	if u.ExpectedSize > s.MaxFile {
		return nil, ErrCapacity
	}
	target, err := s.prepareUploadTarget(ctx, t, u)
	if err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, target.Path)
	if err != nil {
		return nil, err
	}
	chunks, err := t.UploadChunks(ctx, id)
	if err != nil {
		return nil, err
	}
	offset := int64(0)
	for _, c := range chunks {
		if c.Offset != offset {
			return nil, store.ErrState
		}
		offset += c.Size
	}
	if len(chunks) != u.Chunks || offset != u.ExpectedSize {
		return nil, store.ErrState
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, err
	}
	if err = s.Disk.Capacity(u.ExpectedSize, s.MaxStored); err != nil {
		return nil, err
	}
	file := &store.File{ID: secure.NewID(), Size: u.ExpectedSize, SHA256: u.ExpectedSHA, Policy: "integrity-only-v1"}
	if err = t.ConfigureIntakeFile(ctx, file); err != nil {
		return nil, err
	}
	source := &uploadReader{ctx: ctx, disk: s.Disk, scope: scope, chunks: chunks}
	defer source.Close()
	err = s.Disk.Stage(Name(scope.Tenant, scope.Partner, file.ID), source, file.Size, file.SHA256)
	if err != nil {
		if !errors.Is(err, ErrIntegrity) {
			return nil, err
		}
		next := *u
		next.State = "rejected"
		next.Revision++
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		if err = t.SaveUpload(ctx, u, &next, "UploadRejected", nil); err != nil {
			return nil, err
		}
		result, err := finishUpload(ctx, t, key, meaning, &next, nil)
		if err != nil {
			return nil, err
		}
		return result, ErrIntegrity
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = s.checkUploadStorage(u); err != nil {
		return nil, err
	}
	acceptedKey := "upload-file-" + id
	if err = t.AcceptUpload(ctx, acceptedKey, pathMeaning(file.Size, file.SHA256, actual, &target), file, id, u.StorageID); err != nil {
		return nil, err
	}
	command := targetCommand(&target, file.ID)
	held, err := t.BindIntake(ctx, file, s.Disk.Identity(), &command)
	if err != nil {
		return nil, err
	}
	if !held {
		if _, err = t.ApplyPathCommand(ctx, acceptedKey, command, s.NamespaceMaxEntries); err != nil {
			return nil, err
		}
	}
	next := *u
	next.State = "completed"
	next.FileID = file.ID
	next.Revision++
	if err = t.SaveUpload(ctx, u, &next, "UploadCompleted", nil); err != nil {
		return nil, err
	}
	return finishUpload(ctx, t, key, meaning, &next, file)
}

type uploadReader struct {
	ctx     context.Context
	disk    *Disk
	scope   store.Scope
	chunks  []store.UploadChunk
	index   int
	current *os.File
}

func (r *uploadReader) Close() error {
	if r.current != nil {
		err := r.current.Close()
		r.current = nil
		return err
	}
	return nil
}
func (r *uploadReader) Read(p []byte) (int, error) {
	for {
		if err := r.ctx.Err(); err != nil {
			return 0, err
		}
		if r.current == nil {
			if r.index >= len(r.chunks) {
				return 0, io.EOF
			}
			c := r.chunks[r.index]
			f, err := r.disk.VerifiedContext(r.ctx, Name(r.scope.Tenant, r.scope.Partner, c.ObjectID), c.Size, c.SHA256)
			if err != nil {
				return 0, err
			}
			r.current = f
			r.index++
		}
		n, err := r.current.Read(p)
		if err == io.EOF {
			r.current.Close()
			r.current = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}
