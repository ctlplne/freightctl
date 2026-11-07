package custody

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var ErrNamespaceParent = errors.New("destination parent collection required")
var ErrNamespaceFileProfile = errors.New("namespace operation requires a file")

// MoveFileIfCurrent changes one authorized virtual mapping,not the immutable
// bytes or their custody identity. Conditions and the ordinary rename command
// share the namespace lock and commit their event/receipt together.
func (s *Service) MoveFileIfCurrent(ctx context.Context, scope store.Scope, key, source, target, fileID, digest string) (*store.PathResult, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(fileID) || !digestPattern.MatchString(digest) {
		return nil, ErrInput
	}
	for _, name := range []string{source, target} {
		canonical, err := vpath.Canonical(name)
		if err != nil || canonical != name || canonical == "/" || vpath.ControlPath(canonical) {
			return nil, vpath.ErrPath
		}
	}
	if source == target {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for _, permission := range []string{"manage_paths", "read"} {
		if err = t.Require(permission); err != nil {
			return nil, err
		}
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, source)
	if err != nil {
		return nil, err
	}
	if err = t.CheckAncestors(ctx, actual); err != nil {
		return nil, err
	}
	entry, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, err
	}
	mask := uint32(4)
	if entry.Kind == "dir" {
		mask = 5
	}
	if err = t.EntryMode(entry, mask); err != nil {
		return nil, err
	}
	if entry.Kind != "file" {
		return nil, ErrNamespaceFileProfile
	}
	if err = t.FileAccessible(ctx, entry.FileID); err != nil {
		return nil, err
	}
	file, err := t.File(ctx, entry.FileID)
	if err != nil {
		return nil, err
	}
	if file.ID != fileID || file.SHA256 != digest {
		return nil, store.ErrRevision
	}
	destination, err := vpath.Resolve(t.Root, target)
	if err != nil {
		return nil, err
	}
	if err = t.ParentWritable(ctx, destination); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNamespaceParent
		}
		return nil, err
	}
	result, err := t.ApplyPathCommand(ctx, key, store.PathCommand{Operation: "rename", Path: source, Target: target, FileID: file.ID, ExpectedRevision: &entry.Revision}, s.NamespaceMaxEntries)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.FileAccessible(ctx, entry.FileID); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
