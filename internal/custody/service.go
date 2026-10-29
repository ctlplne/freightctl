package custody

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var ErrInput = errors.New("invalid upload length, digest or idempotency key")

type Service struct {
	DB                    *store.Store
	Disk                  *Disk
	MaxFile, MaxStored    int64
	ReconcileMaxBytes     int64
	UploadCheckpointBytes int
	NamespaceMaxEntries   int
}

func (s *Service) Accept(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader) (*store.File, bool, error) {
	return s.accept(ctx, scope, key, size, digest, body, nil)
}

func (s *Service) accept(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader, target *UploadTarget) (*store.File, bool, error) {
	if size < 0 || size > s.MaxFile || !digestPattern.MatchString(digest) || !keyPattern.MatchString(key) {
		return nil, false, ErrInput
	}
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, false, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("write"); err != nil {
		return nil, false, err
	}
	if target == nil && t.Root != "/" {
		return nil, false, store.ErrForbidden
	}
	meaning := store.Meaning(size, digest)
	if target != nil {
		actual, err := vpath.Resolve(t.Root, target.Path)
		if err != nil {
			return nil, false, err
		}
		if target.Mode != nil && *target.Mode > 0777 {
			return nil, false, ErrInput
		}
		meaning = pathMeaning(size, digest, actual, target)
	}
	prior, err := t.Replay(ctx, key, meaning)
	if err != nil {
		return nil, false, err
	}
	if prior != nil {
		if err = t.Reauthorize(ctx); err != nil {
			return nil, false, err
		}
		if err = t.Require("write"); err != nil {
			return nil, false, err
		}
		if err = t.FileAccessibleMode(ctx, prior.ID, 2); err != nil {
			return nil, false, err
		}
		return prior, true, t.Tx.Commit(ctx)
	}
	if target != nil {
		var used bool
		if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM namespace_commands WHERE actor_id=$1 AND request_key=$2)`, t.Actor, key).Scan(&used); err != nil {
			return nil, false, err
		}
		if used {
			return nil, false, store.ErrConflict
		}
		if _, err = prepareTarget(ctx, t, target); err != nil {
			return nil, false, err
		}
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
	if target != nil {
		if _, err = t.ApplyPathCommand(ctx, key, targetCommand(target, f.ID), s.NamespaceMaxEntries); err != nil {
			return nil, false, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
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
	f, data, err := s.openAuthorized(ctx, t, id)
	if err != nil {
		return nil, nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		data.Close()
		return nil, nil, err
	}
	return f, data, nil
}
