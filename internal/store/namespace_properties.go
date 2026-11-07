package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ctlplne/freightctl/internal/namespaceprops"
)

func propertyError(err error) error {
	switch {
	case errors.Is(err, namespaceprops.ErrProtected):
		return ErrForbidden
	case errors.Is(err, namespaceprops.ErrLimit):
		return ErrLimit
	case err != nil:
		return ErrState
	default:
		return nil
	}
}

// EntryProperties is separate from PathEntry: ordinary listings,stat results
// and model context do not acquire arbitrary file-supplied XML content.
func (t *Transaction) EntryProperties(ctx context.Context, entry *PathEntry) (map[string]string, error) {
	if err := t.Require("read"); err != nil {
		return nil, err
	}
	current, err := t.Entry(ctx, entry.Path)
	if err != nil {
		return nil, err
	}
	if current.ID != entry.ID || current.Revision != entry.Revision {
		return nil, ErrRevision
	}
	entry = current
	if err := t.CheckAncestors(ctx, entry.Path); err != nil {
		return nil, err
	}
	mask := uint32(4)
	if entry.Kind == "dir" {
		mask = 5
	}
	if err := t.EntryMode(entry, mask); err != nil {
		return nil, err
	}
	if entry.Kind == "file" {
		if err := t.FileAccessible(ctx, entry.FileID); err != nil {
			return nil, err
		}
	}
	if entry.ID == "" && entry.Path == "/" {
		return map[string]string{}, nil
	}
	var encoded []byte
	if err := t.Tx.QueryRow(ctx, `SELECT namespace_properties FROM namespace_entries WHERE entry_id=$1 AND revision=$2 AND NOT deleted`, entry.ID, entry.Revision).Scan(&encoded); err != nil {
		return nil, err
	}
	var properties map[string]string
	if err := json.Unmarshal(encoded, &properties); err != nil {
		return nil, err
	}
	if err := propertyError(namespaceprops.Validate(properties)); err != nil {
		return nil, err
	}
	return properties, nil
}

func (t *Transaction) propertyTarget(ctx context.Context, actual string, command PathCommand) (*PathEntry, error) {
	for _, permission := range []string{"read", "write", "manage_paths"} {
		if err := t.Require(permission); err != nil {
			return nil, err
		}
	}
	if err := t.CheckAncestors(ctx, actual); err != nil {
		return nil, err
	}
	entry, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, err
	}
	mask := uint32(6)
	if entry.Kind == "dir" {
		mask = 7
	}
	if err = t.EntryMode(entry, mask); err != nil {
		return nil, err
	}
	if entry.ID != command.ExpectedEntryID {
		return nil, ErrRevision
	}
	if entry.Kind == "file" {
		if err = t.FileAccessible(ctx, entry.FileID); err != nil {
			return nil, err
		}
	}
	return entry, nil
}
