package store

import (
	"context"

	"github.com/ctlplne/freightctl/internal/vpath"
)

func validateTreeMove(command PathCommand) error {
	if !ValidID(command.ExpectedEntryID) || command.ExpectedRevision == nil || *command.ExpectedRevision < 1 || command.Target == "" || command.FileID != "" || command.ExpectedFileID != "" || command.Replace || command.TargetRevision != nil || command.Mode != nil || command.Modified != nil || len(command.PropertyChanges) != 0 {
		return ErrState
	}
	source, err := vpath.Canonical(command.Path)
	if err != nil || source != command.Path {
		return vpath.ErrPath
	}
	target, err := vpath.Canonical(command.Target)
	if err != nil || target != command.Target {
		return vpath.ErrPath
	}
	if source == "/" || target == "/" || vpath.ControlPath(source) || vpath.ControlPath(target) || source == target || vpath.Within(source, target) {
		return ErrForbidden
	}
	return nil
}

// Validate every member before any transition. The caller holds the exclusive
// namespace lock. A hidden,held,or excessive subtree fails as a whole;no prefix
// is moved and no opaque child can be rescued by a readable file alias.
func (t *Transaction) prepareTreeMove(ctx context.Context, actual string, command PathCommand) ([]PathEntry, error) {
	if err := t.CheckAncestors(ctx, actual); err != nil {
		return nil, err
	}
	root, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, err
	}
	if err = t.EntryMode(root, 5); err != nil {
		return nil, err
	}
	if root.Kind != "dir" {
		return nil, ErrState
	}
	if root.ID != command.ExpectedEntryID {
		return nil, ErrRevision
	}
	rows, err := t.Tx.Query(ctx, "SELECT "+entryColumns+entryJoin+` WHERE NOT n.deleted AND (n.path=$1 OR left(n.path,length($1)+1)=$1||'/') ORDER BY length(n.path),n.path LIMIT 1001`, actual)
	if err != nil {
		return nil, err
	}
	tree := make([]PathEntry, 0)
	for rows.Next() {
		entry, err := scanEntry(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		tree = append(tree, *entry)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(tree) > 1000 {
		return nil, ErrLimit
	}
	if len(tree) == 0 || tree[0].ID != root.ID {
		return nil, ErrRevision
	}
	directories := map[string]bool{}
	for _, entry := range tree {
		if vpath.ControlPath(entry.Path) {
			return nil, ErrForbidden
		}
		if entry.Path != actual && !directories[entry.Parent] {
			return nil, ErrState
		}
		mask := uint32(4)
		if entry.Kind == "dir" {
			mask = 5
		}
		if err = t.EntryMode(&entry, mask); err != nil {
			return nil, err
		}
		if entry.Kind == "dir" {
			directories[entry.Path] = true
		} else if entry.Kind == "file" {
			if err = t.FileAvailable(ctx, entry.FileID); err != nil {
				return nil, err
			}
		} else {
			return nil, ErrState
		}
	}
	return tree, nil
}
