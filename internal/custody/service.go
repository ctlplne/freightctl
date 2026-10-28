package custody

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var ErrInput = errors.New("invalid upload length, digest or idempotency key")

type Service struct {
	DB                 *store.Store
	Disk               *Disk
	MaxFile, MaxStored int64
}

func (s *Service) Accept(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader) (*store.File, bool, error) {
	if size < 0 || size > s.MaxFile || !digestPattern.MatchString(digest) || !keyPattern.MatchString(key) {
		return nil, false, ErrInput
	}
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, false, err
	}
	defer t.Tx.Rollback(ctx)
	meaning := store.Meaning(size, digest)
	prior, err := t.Replay(ctx, key, meaning)
	if err != nil {
		return nil, false, err
	}
	if prior != nil {
		return prior, true, t.Tx.Commit(ctx)
	}
	// Initial single-storage profile serializes capacity checks and staging across processes.
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(721815034)`); err != nil {
		return nil, false, err
	}
	if err = s.Disk.Capacity(size, s.MaxStored); err != nil {
		return nil, false, err
	}
	f := &store.File{ID: secure.NewID(), Size: size, SHA256: digest, Policy: "integrity-only-v1"}
	if err = s.Disk.Stage(Name(scope.Tenant, scope.Partner, f.ID), body, size, digest); err != nil {
		return nil, false, err
	}
	// Once synced, retain bytes even if SQL commit is uncertain. A retry reconciles by request key.
	if err = t.Accept(ctx, key, meaning, f); err != nil {
		return nil, false, err
	}
	return f, false, t.Tx.Commit(ctx)
}
func (s *Service) Download(ctx context.Context, scope store.Scope, id string) (*store.File, *os.File, error) {
	if !store.ValidID(id) {
		return nil, nil, store.ErrNotFound
	}
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(ctx)
	f, err := t.File(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	data, err := s.Disk.Verified(Name(scope.Tenant, scope.Partner, f.ID), f.Size, f.SHA256)
	if err != nil {
		return nil, nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		data.Close()
		return nil, nil, err
	}
	_, err = t.Append(ctx, "FileDownloadAuthorized", id, map[string]string{"sha256": f.SHA256})
	if err == nil {
		err = t.Tx.Commit(ctx)
	}
	if err != nil {
		data.Close()
		return nil, nil, err
	}
	return f, data, nil
}
