package custody

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type NamespaceProperty struct {
	Entry store.PathEntry
	File  *store.File
}

// ReadNamespaceProperties returns one finite namespace snapshot. Unavailable or
// unreadable children are opaque, not metadata that can rescue a later GET.
// A shared namespace transaction lock prevents rename/replacement halfway
// through discovery. Opening bytes still performs the ordinary integrity and
// current-authority checks in OpenPathReader.
func (s *Service) ReadNamespaceProperties(ctx context.Context, scope store.Scope, virtual string, children bool) ([]NamespaceProperty, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	if err = t.Require("read"); err == nil {
		err = t.Require("list")
	}
	if err != nil {
		return nil, err
	}
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return nil, err
	}
	// Writers already use this same key exclusively. Keep it shared for readers.
	if _, err = t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, scope.Tenant+":"+scope.Partner+":namespace-v1"); err != nil {
		return nil, err
	}
	if err = t.CheckAncestors(ctx, actual); err != nil {
		return nil, err
	}
	entry, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, err
	}
	property := func(e store.PathEntry) (NamespaceProperty, error) {
		mask := uint32(4)
		if e.Kind == "dir" {
			mask = 5
		}
		if err := t.EntryMode(&e, mask); err != nil {
			return NamespaceProperty{}, err
		}
		view, err := t.EntryView(e)
		if err != nil {
			return NamespaceProperty{}, err
		}
		result := NamespaceProperty{Entry: view}
		if e.Kind == "file" {
			if err = t.FileAccessible(ctx, e.FileID); err != nil {
				return NamespaceProperty{}, err
			}
			result.File, err = t.File(ctx, e.FileID)
		}
		return result, err
	}
	self, err := property(*entry)
	if err != nil {
		return nil, err
	}
	result := []NamespaceProperty{self}
	if children && entry.Kind == "dir" {
		entries, more, err := t.ListEntries(ctx, actual, "", 1000)
		if err != nil {
			return nil, err
		}
		if more {
			return nil, store.ErrLimit
		}
		for _, child := range entries {
			if vpath.ControlPath(child.Path) {
				continue
			}
			p, err := property(child)
			if errors.Is(err, store.ErrForbidden) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrState) {
				continue
			}
			if err != nil {
				return nil, err
			}
			result = append(result, p)
		}
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}
