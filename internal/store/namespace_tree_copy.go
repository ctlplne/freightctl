package store

import (
	"context"
	"errors"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// PrepareTreeCopy holds the namespace lock until the enclosing transaction
// ends. Custody verifies each distinct immutable file before ApplyPathCommand
// publishes any new mapping;the store repeats this same current preflight.
func (t *Transaction) PrepareTreeCopy(ctx context.Context, command PathCommand) ([]PathEntry, error) {
	if command.Operation != "copy_tree" && command.Operation != "copy_dir" {
		return nil, ErrState
	}
	for _, permission := range []string{"read", "list", "write"} {
		if err := t.Require(permission); err != nil {
			return nil, err
		}
	}
	if err := validateTreeMove(command); err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, command.Path)
	if err != nil {
		return nil, err
	}
	target, err := vpath.Resolve(t.Root, command.Target)
	if err != nil {
		return nil, err
	}
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	if err = t.ParentWritable(ctx, target); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrState
		}
		return nil, err
	}
	tree, err := t.prepareTreeMutation(ctx, actual, command)
	if err != nil {
		return nil, err
	}
	for _, entry := range tree {
		path := target + strings.TrimPrefix(entry.Path, actual)
		if canonical, err := vpath.Canonical(path); err != nil || canonical != path {
			return nil, vpath.ErrPath
		}
	}
	return tree, nil
}

func (t *Transaction) copyPreparedTree(ctx context.Context, actual string, command PathCommand, tree []PathEntry, commandID string, maxEntries int) (*PathEntry, error) {
	target, err := vpath.Resolve(t.Root, command.Target)
	if err != nil {
		return nil, err
	}
	var occupied bool
	if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM namespace_entries WHERE NOT deleted AND (path=$1 OR left(path,length($1)+1)=$1||'/'))`, target).Scan(&occupied); err != nil {
		return nil, err
	}
	if occupied {
		return nil, ErrExists
	}
	if maxEntries < 1 {
		maxEntries = 10000
	}
	var total int
	if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM namespace_entries WHERE NOT deleted`).Scan(&total); err != nil {
		return nil, err
	}
	if len(tree) == 0 || total > maxEntries-len(tree) {
		return nil, ErrLimit
	}
	var root *PathEntry
	now := time.Now().UTC()
	for _, source := range tree {
		properties, err := t.EntryProperties(ctx, &source)
		if err != nil {
			return nil, err
		}
		if len(properties) == 0 {
			properties = nil
		}
		next := PathEntry{ID: secure.NewID(), Path: target + strings.TrimPrefix(source.Path, actual), Owner: t.Actor, Revision: 1, Modified: now, Kind: source.Kind, Mode: 0640, FileID: source.FileID, Size: source.Size}
		kind := "PathPublished"
		if source.Kind == "dir" {
			next.Mode = 0750
			kind = "PathCreated"
			if err = t.SaveEntry(ctx, nil, &next, kind, commandID); err != nil {
				return nil, err
			}
			if properties != nil {
				// The existing SQL guard allows property initialization only by
				// its exact attrs event. Keep it intact:both events commit atomically.
				created := next
				next.Revision++
				if err = t.saveEntryProperties(ctx, &created, &next, "PathAttrsChanged", commandID, properties); err != nil {
					return nil, err
				}
			}
		} else {
			if err = t.saveEntryProperties(ctx, nil, &next, kind, commandID, properties); err != nil {
				return nil, err
			}
		}
		if source.Path == actual {
			copied := next
			root = &copied
		}
	}
	for _, source := range tree {
		if source.Kind == "file" {
			if err = t.FileAccessible(ctx, source.FileID); err != nil {
				return nil, err
			}
		}
	}
	if root == nil {
		return nil, ErrState
	}
	return root, nil
}
