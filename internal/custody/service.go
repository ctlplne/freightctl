package custody

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var ErrInput = errors.New("invalid upload length, digest or idempotency key")

// Acceptance describes what the original upload committed, not a later check
// verdict. A replay retains this meaning even after the file is released.
func Acceptance(file *store.File) string {
	if strings.HasPrefix(file.Policy, "intake-csv-v1:") {
		return "durable-held-pending-checks-and-release"
	}
	return "durable-local-integrity-only"
}

type Service struct {
	DB                    *store.Store
	Disk                  *Disk
	MaxFile, MaxStored    int64
	ReconcileMaxBytes     int64
	UploadCheckpointBytes int
	NamespaceMaxEntries   int
	Exchanges             ExchangeSettings
}

func (s *Service) Accept(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader) (*store.File, bool, error) {
	return s.accept(ctx, scope, key, size, digest, body, nil, nil, nil)
}

func (s *Service) accept(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader, target *UploadTarget, sealed *sealedAcceptance, copySource *receivedCopy) (*store.File, bool, error) {
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
	if copySource != nil {
		meaning = store.ExchangeCopyMeaning(copySource.request, meaning)
	}
	prior, err := t.Replay(ctx, key, meaning)
	if err != nil {
		return nil, false, err
	}
	if prior != nil {
		if sealed != nil && prior.ID != sealed.id {
			return nil, false, store.ErrConflict
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, false, err
		}
		if err = t.Require("write"); err != nil {
			return nil, false, err
		}
		if err = t.FileReceiptAccessible(ctx, prior.ID); err != nil {
			return nil, false, err
		}
		return prior, true, t.Tx.Commit(ctx)
	}
	if copySource != nil {
		reader, openErr := copySource.open(ctx, t, s)
		if openErr != nil {
			return nil, false, openErr
		}
		defer reader.Close()
		body = reader
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
	incoming := size
	if sealed != nil {
		incoming = 0
	} // Already sealed bytes are included in disk usage.
	if err = s.Disk.Capacity(incoming, s.MaxStored); err != nil {
		return nil, false, err
	}
	f := &store.File{ID: secure.NewID(), Size: size, SHA256: digest, Policy: "integrity-only-v1"}
	if sealed != nil {
		f.ID = sealed.id
	}
	if err = t.ConfigureIntakeFile(ctx, f); err != nil {
		return nil, false, err
	}
	if sealed == nil {
		if err = s.Disk.Stage(Name(scope.Tenant, scope.Partner, f.ID), body, size, digest); err != nil {
			return nil, false, err
		}
	}
	// Once synced, retain bytes even if SQL commit is uncertain. A retry reconciles by request key.
	if copySource != nil {
		err = t.AcceptExchangeCopy(ctx, key, meaning, f, s.Disk.Identity(), copySource.request.ExchangeCopyOrigin)
	} else {
		err = t.Accept(ctx, key, meaning, f)
	}
	if err != nil {
		return nil, false, err
	}
	var command *store.PathCommand
	if target != nil {
		value := targetCommand(target, f.ID)
		command = &value
	}
	held, err := t.BindIntake(ctx, f, s.Disk.Identity(), command)
	if err != nil {
		return nil, false, err
	}
	if target != nil && !held && sealed == nil {
		if _, err = t.ApplyPathCommand(ctx, key, targetCommand(target, f.ID), s.NamespaceMaxEntries); err != nil {
			return nil, false, err
		}
	}
	if sealed != nil {
		if err = sealed.bind(ctx, t, f, held); err != nil {
			return nil, false, err
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, false, err
	}
	if copySource != nil {
		if err = copySource.check(ctx, t, s); err != nil {
			return nil, false, err
		}
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
