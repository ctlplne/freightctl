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

type PathPage struct {
	Entries []store.PathEntry `json:"entries"`
	Next    string            `json:"next,omitempty"`
}
type UploadTarget struct {
	Path             string
	ExpectedRevision *int64
	Mode             *uint32
	Modified         *time.Time
	// Omit false so historical ordinary upload request meanings stay identical.
	RequireAbsent bool `json:"require_absent,omitempty"`
}

func (s *Service) PathCommand(ctx context.Context, scope store.Scope, key string, command store.PathCommand) (*store.PathResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if command.Operation == "publish" {
		if err = t.Require("write"); err != nil {
			return nil, err
		}
		if err = t.Require("read"); err != nil {
			return nil, err
		}
		if err = t.FileAccessible(ctx, command.FileID); err != nil {
			return nil, err
		}
		file, err := t.File(ctx, command.FileID)
		if err != nil {
			return nil, err
		}
		if s.Disk == nil {
			return nil, store.ErrState
		}
		data, err := s.Disk.VerifiedContext(ctx, Name(scope.Tenant, scope.Partner, file.ID), file.Size, file.SHA256)
		if err != nil {
			return nil, err
		}
		data.Close()
	}
	result, err := t.ApplyPathCommand(ctx, key, command, s.NamespaceMaxEntries)
	if err != nil {
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
func (s *Service) StatPath(ctx context.Context, scope store.Scope, virtual string) (*store.PathEntry, error) {
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("list"); err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return nil, err
	}
	if err = t.CheckAncestors(ctx, actual); err != nil {
		return nil, err
	}
	e, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, err
	}
	view, err := t.EntryView(*e)
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
func (s *Service) ListPath(ctx context.Context, scope store.Scope, virtual, after string, limit int) (*PathPage, error) {
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return nil, err
	}
	actualAfter := ""
	if after != "" {
		actualAfter, err = vpath.Resolve(t.Root, after)
		if err != nil {
			return nil, err
		}
	}
	entries, more, err := t.ListEntries(ctx, actual, actualAfter, limit)
	if err != nil {
		return nil, err
	}
	page := &PathPage{Entries: make([]store.PathEntry, 0, len(entries))}
	for _, entry := range entries {
		view, err := t.EntryView(entry)
		if err != nil {
			return nil, err
		}
		page.Entries = append(page.Entries, view)
	}
	if more {
		page.Next = page.Entries[len(page.Entries)-1].Path
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return page, nil
}
func (s *Service) DownloadPath(ctx context.Context, scope store.Scope, virtual string) (*store.File, *os.File, error) {
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("read"); err != nil {
		return nil, nil, err
	}
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return nil, nil, err
	}
	if err = t.CheckAncestors(ctx, actual); err != nil {
		return nil, nil, err
	}
	e, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, nil, err
	}
	if e.Kind != "file" {
		return nil, nil, store.ErrState
	}
	if err = t.EntryMode(e, 4); err != nil {
		return nil, nil, err
	}
	f, data, err := s.openAuthorized(ctx, t, e.FileID)
	if err != nil {
		return nil, nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		data.Close()
		return nil, nil, err
	}
	return f, data, nil
}
func (s *Service) openAuthorized(ctx context.Context, t *store.Transaction, id string) (*store.File, *os.File, error) {
	if err := t.Require("read"); err != nil {
		return nil, nil, err
	}
	if err := t.FileAccessible(ctx, id); err != nil {
		return nil, nil, err
	}
	f, err := t.File(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	data, err := s.Disk.VerifiedContext(ctx, Name(t.Scope.Tenant, t.Scope.Partner, f.ID), f.Size, f.SHA256)
	if err != nil {
		return nil, nil, err
	}
	if err = t.Reauthorize(ctx); err == nil {
		err = t.Require("read")
	}
	if err == nil {
		err = t.FileAccessible(ctx, id)
	}
	if err == nil {
		_, err = t.Append(ctx, "FileDownloadAuthorized", id, map[string]string{"sha256": f.SHA256, "protocol_session_id": t.Scope.SessionID})
	}
	if err != nil {
		data.Close()
		return nil, nil, err
	}
	return f, data, nil
}
func (s *Service) AcceptAt(ctx context.Context, scope store.Scope, key string, size int64, digest string, body io.Reader, target UploadTarget) (*store.File, bool, error) {
	if target.RequireAbsent && target.ExpectedRevision != nil {
		return nil, false, ErrInput
	}
	canonical, err := vpath.Canonical(target.Path)
	if err != nil || canonical == "/" || vpath.ControlPath(canonical) {
		return nil, false, vpath.ErrPath
	}
	target.Path = canonical
	if target.Modified != nil {
		normalized := target.Modified.UTC().Truncate(time.Microsecond)
		target.Modified = &normalized
	}
	return s.accept(ctx, scope, key, size, digest, body, &target, nil, nil)
}
func pathMeaning(size int64, digest, actual string, target *UploadTarget) string {
	b, _ := json.Marshal(struct {
		Base, Actual string
		Target       UploadTarget
	}{store.Meaning(size, digest), actual, *target})
	return secure.Digest(b)
}
func targetCommand(target *UploadTarget, id string) store.PathCommand {
	return store.PathCommand{Operation: "publish", Path: target.Path, FileID: id, ExpectedRevision: target.ExpectedRevision, Replace: target.ExpectedRevision != nil, Mode: target.Mode, Modified: target.Modified}
}
func prepareTarget(ctx context.Context, t *store.Transaction, target *UploadTarget) (string, error) {
	actual, err := vpath.Resolve(t.Root, target.Path)
	if err != nil {
		return "", err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return "", err
	}
	if err = t.ParentWritable(ctx, actual); err != nil {
		return "", err
	}
	old, err := t.Entry(ctx, actual)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", err
	}
	if old == nil {
		if target.ExpectedRevision != nil {
			return "", store.ErrRevision
		}
	} else {
		if old.Kind != "file" || target.ExpectedRevision == nil || *target.ExpectedRevision != old.Revision {
			return "", store.ErrRevision
		}
		if err = t.EntryMode(old, 2); err != nil {
			return "", err
		}
	}
	return actual, nil
}
