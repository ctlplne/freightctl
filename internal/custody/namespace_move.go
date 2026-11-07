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
	return s.changeFileIfCurrent(ctx, scope, key, "rename", source, target, fileID, digest, false)
}

// Overwriting is a separate explicit decision. Destination mode,availability
// and mapping revision are checked under the same lock as removal and rename.
func (s *Service) MoveFileOverwritingIfCurrent(ctx context.Context, scope store.Scope, key, source, target, fileID, digest string) (*store.PathResult, error) {
	return s.changeFileIfCurrent(ctx, scope, key, "rename", source, target, fileID, digest, true)
}

// RemoveFileIfCurrent removes one published mapping, never the immutable file
// or custody history. Receiving or reading a file grants no removal authority.
func (s *Service) RemoveFileIfCurrent(ctx context.Context, scope store.Scope, key, source, fileID, digest string) (*store.PathResult, error) {
	return s.changeFileIfCurrent(ctx, scope, key, "remove", source, "", fileID, digest, false)
}

// CopyFileIfCurrent verifies the exact immutable bytes before publishing a
// distinct mapping. The original mapping and immutable custody do not change.
func (s *Service) CopyFileIfCurrent(ctx context.Context, scope store.Scope, key, source, target, fileID, digest string) (*store.PathResult, error) {
	return s.changeFileIfCurrent(ctx, scope, key, "copy", source, target, fileID, digest, false)
}

func (s *Service) changeFileIfCurrent(ctx context.Context, scope store.Scope, key, operation, source, target, fileID, digest string, overwrite bool) (*store.PathResult, error) {
	if !keyPattern.MatchString(key) || !store.ValidID(fileID) || !digestPattern.MatchString(digest) {
		return nil, ErrInput
	}
	if overwrite && operation != "rename" {
		return nil, ErrInput
	}
	names := []string{source}
	if operation == "rename" || operation == "copy" {
		names = append(names, target)
	}
	for _, name := range names {
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
	permission := "manage_paths"
	if operation == "copy" {
		permission = "write"
	}
	for _, permission := range []string{permission, "read"} {
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
	command := store.PathCommand{Operation: operation, Path: source, Target: target, FileID: file.ID, ExpectedRevision: &entry.Revision}
	if operation == "rename" || operation == "copy" {
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
		if operation == "copy" {
			if _, err = t.Entry(ctx, destination); err == nil {
				return nil, store.ErrExists
			} else if !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
		}
		if overwrite {
			command.Replace = true
			existing, err := t.Entry(ctx, destination)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			if existing != nil {
				if err = t.EntryMode(existing, 2); err != nil {
					return nil, err
				}
				if existing.Kind != "file" {
					return nil, ErrNamespaceFileProfile
				}
				if err = t.FileAvailable(ctx, existing.FileID); err != nil {
					return nil, err
				}
				revision := existing.Revision
				command.TargetRevision = &revision
			}
		}
	}
	if operation == "copy" {
		if err = s.verifyNamespacePublication(ctx, scope, file); err != nil {
			return nil, err
		}
	}
	result, err := t.ApplyPathCommand(ctx, key, command, s.NamespaceMaxEntries)
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if operation == "remove" {
		// The successful command intentionally removed the readable mapping.
		// Recheck current intake without treating its absence as a new grant.
		err = t.FileAvailable(ctx, entry.FileID)
	} else {
		err = t.FileAccessible(ctx, entry.FileID)
	}
	if err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
