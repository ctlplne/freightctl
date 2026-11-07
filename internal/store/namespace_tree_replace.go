package store

import (
	"context"

	"github.com/ctlplne/freightctl/internal/vpath"
)

func (t *Transaction) prepareTreeReplacement(ctx context.Context, command PathCommand) ([]PathEntry, error) {
	target, err := vpath.Resolve(t.Root, command.Target)
	if err != nil {
		return nil, err
	}
	selection := PathCommand{Operation: "remove_tree", Path: command.Target, ExpectedEntryID: command.TargetEntryID, ExpectedRevision: command.TargetRevision}
	tree, err := t.prepareTreeMutation(ctx, target, selection)
	if err != nil {
		return nil, err
	}
	if len(tree) == 0 || tree[0].Revision != *command.TargetRevision {
		return nil, ErrRevision
	}
	for _, entry := range tree {
		if entry.Kind == "file" {
			if err = t.EntryMode(&entry, 6); err != nil {
				return nil, err
			}
		}
	}
	return tree, nil
}

func (t *Transaction) removePreparedTree(ctx context.Context, tree []PathEntry, commandID string) (*PathEntry, error) {
	if len(tree) == 0 {
		return nil, ErrState
	}
	var root *PathEntry
	for i := len(tree) - 1; i >= 0; i-- {
		entry := tree[i]
		removed := entry
		removed.Revision++
		removed.Deleted = true
		if err := t.SaveEntry(ctx, &entry, &removed, "PathRemoved", commandID); err != nil {
			return nil, err
		}
		if i == 0 {
			root = &removed
		}
	}
	// Removed mappings no longer authorize access;retain the current policy
	// check without granting any new custody-read authority.
	for _, entry := range tree {
		if entry.Kind == "file" {
			if err := t.FileAvailable(ctx, entry.FileID); err != nil {
				return nil, err
			}
		}
	}
	return root, nil
}

func (t *Transaction) treeCopyCapacity(ctx context.Context, maximum, incoming, replacing int) error {
	if maximum < 1 {
		maximum = 10000
	}
	if incoming < 1 || incoming+replacing > 1000 || replacing < 0 {
		return ErrLimit
	}
	var total int
	if err := t.Tx.QueryRow(ctx, `SELECT count(*) FROM namespace_entries WHERE NOT deleted`).Scan(&total); err != nil {
		return err
	}
	if total-replacing > maximum-incoming {
		return ErrLimit
	}
	return nil
}
