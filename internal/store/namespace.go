package store

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
	"github.com/jackc/pgx/v5"
)

type PathEntry struct {
	ID       string    `json:"id"`
	Path     string    `json:"path"`
	Parent   string    `json:"parent"`
	Kind     string    `json:"kind"`
	FileID   string    `json:"file_id,omitempty"`
	Owner    string    `json:"owner_actor_id"`
	Mode     uint32    `json:"mode"`
	Modified time.Time `json:"modified_at"`
	Revision int64     `json:"revision"`
	Deleted  bool      `json:"deleted"`
	EventID  string    `json:"changed_event_id"`
	Size     int64     `json:"size_bytes"`
}

const entryColumns = `n.entry_id::text,n.path,n.parent_path,n.kind,coalesce(n.file_id::text,''),n.owner_actor_id::text,n.mode,n.modified_at,n.revision,n.deleted,n.changed_event_id::text,coalesce(f.size_bytes,0)`
const entryJoin = ` FROM namespace_entries n LEFT JOIN files f ON (f.tenant_id,f.partner_id,f.file_id)=(n.tenant_id,n.partner_id,n.file_id) `

var operationKey = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func scanEntry(row pgx.Row) (*PathEntry, error) {
	e := &PathEntry{}
	err := row.Scan(&e.ID, &e.Path, &e.Parent, &e.Kind, &e.FileID, &e.Owner, &e.Mode, &e.Modified, &e.Revision, &e.Deleted, &e.EventID, &e.Size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}
func (t *Transaction) NamespaceLock(ctx context.Context) error {
	_, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":namespace-v1")
	return err
}
func (t *Transaction) Entry(ctx context.Context, actual string) (*PathEntry, error) {
	if !vpath.Within(t.Root, actual) {
		return nil, ErrNotFound
	}
	if actual == "/" {
		return &PathEntry{Path: "/", Parent: "/", Kind: "dir", Owner: t.Actor, Mode: 0770, Revision: 1}, nil
	}
	return scanEntry(t.Tx.QueryRow(ctx, "SELECT "+entryColumns+entryJoin+` WHERE n.path=$1 AND NOT n.deleted`, actual))
}
func (t *Transaction) EntryMode(e *PathEntry, mask uint32) error {
	if t.Has("admin") {
		return nil
	}
	bits := (e.Mode >> 3) & 7
	if e.Owner == t.Actor {
		bits = (e.Mode >> 6) & 7
	}
	if bits&mask != mask {
		return ErrForbidden
	}
	return nil
}
func (t *Transaction) CheckAncestors(ctx context.Context, actual string) error {
	if !vpath.Within(t.Root, actual) {
		return ErrNotFound
	}
	parent := vpath.Parent(actual)
	if actual == t.Root {
		parent = t.Root
	}
	if !vpath.Within(t.Root, parent) {
		parent = t.Root
	}
	for {
		e, err := t.Entry(ctx, parent)
		if err != nil {
			return err
		}
		if e.Kind != "dir" {
			return ErrState
		}
		if err = t.EntryMode(e, 1); err != nil {
			return err
		}
		if parent == t.Root || parent == "/" {
			return nil
		}
		parent = vpath.Parent(parent)
	}
}
func (t *Transaction) ParentWritable(ctx context.Context, actual string) error {
	if err := t.CheckAncestors(ctx, actual); err != nil {
		return err
	}
	e, err := t.Entry(ctx, vpath.Parent(actual))
	if err != nil {
		return err
	}
	if e.Kind != "dir" {
		return ErrState
	}
	return t.EntryMode(e, 3)
}
func (t *Transaction) SaveEntry(ctx context.Context, old *PathEntry, next *PathEntry, kind, commandID string) error {
	p, err := vpath.Canonical(next.Path)
	if err != nil || p != next.Path || p == "/" {
		return vpath.ErrPath
	}
	next.Parent = vpath.Parent(next.Path)
	next.Modified = next.Modified.UTC().Truncate(time.Microsecond)
	previous := int64(0)
	if old != nil {
		previous = old.Revision
	}
	id, err := t.Append(ctx, kind, next.ID, map[string]any{"path": next.Path, "kind": next.Kind, "file_id": next.FileID, "owner_actor_id": next.Owner, "mode": next.Mode, "revision": next.Revision, "previous_revision": previous, "deleted": next.Deleted, "modified_unix_us": next.Modified.UnixMicro(), "command_id": commandID, "protocol_session_id": t.Scope.SessionID})
	if err != nil {
		return err
	}
	next.EventID = id
	if old == nil {
		_, err = t.Tx.Exec(ctx, `INSERT INTO namespace_entries(tenant_id,partner_id,entry_id,path,parent_path,kind,file_id,owner_actor_id,mode,modified_at,revision,deleted,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,nullif($7,'')::uuid,$8,$9,$10,$11,$12,$13)`, t.Scope.Tenant, t.Scope.Partner, next.ID, next.Path, next.Parent, next.Kind, next.FileID, next.Owner, next.Mode, next.Modified, next.Revision, next.Deleted, next.EventID)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE namespace_entries SET path=$1,parent_path=$2,kind=$3,file_id=nullif($4,'')::uuid,mode=$5,modified_at=$6,revision=$7,deleted=$8,changed_event_id=$9 WHERE entry_id=$10 AND revision=$11`, next.Path, next.Parent, next.Kind, next.FileID, next.Mode, next.Modified, next.Revision, next.Deleted, next.EventID, old.ID, old.Revision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return nil
}

type PathCommand struct {
	Operation        string     `json:"operation"`
	Path             string     `json:"path"`
	Target           string     `json:"target,omitempty"`
	FileID           string     `json:"file_id,omitempty"`
	ExpectedRevision *int64     `json:"expected_revision,omitempty"`
	Replace          bool       `json:"replace,omitempty"`
	TargetRevision   *int64     `json:"target_revision,omitempty"`
	Mode             *uint32    `json:"mode,omitempty"`
	Modified         *time.Time `json:"modified_at,omitempty"`
}
type PathResult struct {
	Entry    PathEntry `json:"entry"`
	Changed  int       `json:"changed"`
	Replayed bool      `json:"replayed"`
}

func (t *Transaction) ApplyPathCommand(ctx context.Context, key string, command PathCommand, maxEntries int) (*PathResult, error) {
	if !operationKey.MatchString(key) {
		return nil, ErrState
	}
	var permission string
	switch command.Operation {
	case "mkdir", "publish":
		permission = "write"
	case "rename", "remove", "rmdir", "setstat":
		permission = "manage_paths"
	default:
		return nil, ErrState
	}
	if err := t.Require(permission); err != nil {
		return nil, err
	}
	virtual, err := vpath.Canonical(command.Path)
	if err != nil {
		return nil, err
	}
	command.Path = virtual
	if virtual == "/" {
		return nil, ErrForbidden
	}
	actual, err := vpath.Resolve(t.Root, virtual)
	if err != nil {
		return nil, err
	}
	if command.Target != "" {
		target, err := vpath.Canonical(command.Target)
		if err != nil {
			return nil, err
		}
		command.Target = target
	}
	if command.Mode != nil && *command.Mode > 0777 {
		return nil, ErrState
	}
	if command.Modified != nil {
		normalized := command.Modified.UTC().Truncate(time.Microsecond)
		command.Modified = &normalized
	}
	meaningBytes, err := json.Marshal(struct {
		Root      string
		Authority int64
		Command   PathCommand
	}{t.Root, t.AuthorityRevision, command})
	if err != nil {
		return nil, err
	}
	meaning := secure.Digest(meaningBytes)
	if err = t.NamespaceLock(ctx); err != nil {
		return nil, err
	}
	var priorHash string
	var prior []byte
	err = t.Tx.QueryRow(ctx, `SELECT request_hash,result FROM namespace_commands WHERE actor_id=$1 AND request_key=$2`, t.Actor, key).Scan(&priorHash, &prior)
	if err == nil {
		if priorHash != meaning {
			return nil, ErrConflict
		}
		var result PathResult
		if err = json.Unmarshal(prior, &result); err != nil {
			return nil, err
		}
		if err = t.Reauthorize(ctx); err != nil {
			return nil, err
		}
		result.Replayed = true
		return &result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	old, lookupErr := t.Entry(ctx, actual)
	if lookupErr != nil && !errors.Is(lookupErr, ErrNotFound) {
		return nil, lookupErr
	}
	commandID := secure.NewID()
	changed := 1
	var next PathEntry
	if command.Operation == "mkdir" || command.Operation == "publish" {
		if err = t.ParentWritable(ctx, actual); err != nil {
			return nil, err
		}
		if old != nil {
			if command.Operation == "mkdir" || !command.Replace {
				return nil, ErrExists
			}
			if old.Kind != "file" || command.ExpectedRevision == nil || *command.ExpectedRevision != old.Revision {
				return nil, ErrRevision
			}
			if err = t.EntryMode(old, 2); err != nil {
				return nil, err
			}
			next = *old
			next.Revision++
		} else {
			if command.ExpectedRevision != nil {
				return nil, ErrRevision
			}
			if maxEntries < 1 {
				maxEntries = 10000
			}
			var total int
			if err = t.Tx.QueryRow(ctx, `SELECT count(*) FROM namespace_entries WHERE NOT deleted`).Scan(&total); err != nil {
				return nil, err
			}
			if total >= maxEntries {
				return nil, ErrLimit
			}
			next = PathEntry{ID: secure.NewID(), Path: actual, Owner: t.Actor, Revision: 1, Modified: time.Now().UTC(), Kind: "dir", Mode: 0750}
		}
		kind := "PathCreated"
		if command.Operation == "publish" {
			if !ValidID(command.FileID) {
				return nil, ErrNotFound
			}
			file, err := t.File(ctx, command.FileID)
			if err != nil {
				return nil, err
			}
			if !t.PendingFiles[file.ID] {
				if err = t.Require("read"); err != nil {
					return nil, err
				}
				if err = t.FileAccessible(ctx, file.ID); err != nil {
					return nil, err
				}
			}
			next.Kind = "file"
			next.FileID = file.ID
			next.Size = file.Size
			if old == nil {
				next.Mode = 0640
			}
			kind = "PathPublished"
		}
		if command.Mode != nil {
			if old != nil && !t.Has("admin") && old.Owner != t.Actor {
				return nil, ErrForbidden
			}
			next.Mode = *command.Mode
		}
		if command.Modified != nil {
			next.Modified = *command.Modified
		}
		if err = t.SaveEntry(ctx, old, &next, kind, commandID); err != nil {
			return nil, err
		}
	} else {
		if old == nil {
			return nil, ErrNotFound
		}
		if command.ExpectedRevision == nil || *command.ExpectedRevision != old.Revision {
			return nil, ErrRevision
		}
		if err = t.CheckAncestors(ctx, actual); err != nil {
			return nil, err
		}
		next = *old
		next.Revision++
		switch command.Operation {
		case "setstat":
			if !t.Has("admin") && old.Owner != t.Actor {
				return nil, ErrForbidden
			}
			if command.Mode == nil && command.Modified == nil {
				return nil, ErrState
			}
			if command.Mode != nil {
				next.Mode = *command.Mode
			}
			if command.Modified != nil {
				next.Modified = *command.Modified
			}
			if err = t.SaveEntry(ctx, old, &next, "PathAttrsChanged", commandID); err != nil {
				return nil, err
			}
		case "remove", "rmdir":
			if err = t.ParentWritable(ctx, actual); err != nil {
				return nil, err
			}
			if (command.Operation == "rmdir") != (old.Kind == "dir") {
				return nil, ErrState
			}
			if old.Kind == "dir" {
				var exists bool
				if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM namespace_entries WHERE parent_path=$1 AND NOT deleted)`, actual).Scan(&exists); err != nil {
					return nil, err
				}
				if exists {
					return nil, ErrState
				}
			}
			next.Deleted = true
			if err = t.SaveEntry(ctx, old, &next, "PathRemoved", commandID); err != nil {
				return nil, err
			}
		case "rename":
			if command.Target == "" || command.Target == "/" {
				return nil, ErrForbidden
			}
			target, err := vpath.Resolve(t.Root, command.Target)
			if err != nil {
				return nil, err
			}
			if actual == target {
				next = *old
				changed = 0
				break
			}
			if vpath.Within(actual, target) {
				return nil, ErrState
			}
			if err = t.ParentWritable(ctx, actual); err != nil {
				return nil, err
			}
			if err = t.ParentWritable(ctx, target); err != nil {
				return nil, err
			}
			existing, err := t.Entry(ctx, target)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, err
			}
			if existing != nil {
				if !command.Replace {
					return nil, ErrExists
				}
				if command.TargetRevision == nil || *command.TargetRevision != existing.Revision || existing.Kind != old.Kind {
					return nil, ErrRevision
				}
				if existing.Kind == "dir" {
					var full bool
					if err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM namespace_entries WHERE parent_path=$1 AND NOT deleted)`, target).Scan(&full); err != nil {
						return nil, err
					}
					if full {
						return nil, ErrState
					}
				}
				removed := *existing
				removed.Revision++
				removed.Deleted = true
				if err = t.SaveEntry(ctx, existing, &removed, "PathRemoved", commandID); err != nil {
					return nil, err
				}
				changed++
			}
			rows, err := t.Tx.Query(ctx, "SELECT "+entryColumns+entryJoin+` WHERE NOT n.deleted AND (n.path=$1 OR left(n.path,length($1)+1)=$1||'/') ORDER BY length(n.path),n.path LIMIT 1001`, actual)
			if err != nil {
				return nil, err
			}
			tree := make([]PathEntry, 0)
			for rows.Next() {
				e, err := scanEntry(rows)
				if err != nil {
					rows.Close()
					return nil, err
				}
				tree = append(tree, *e)
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				return nil, err
			}
			if len(tree) > 1000 {
				return nil, ErrLimit
			}
			changed += len(tree) - 1
			for _, entry := range tree {
				moved := entry
				moved.Path = target + strings.TrimPrefix(entry.Path, actual)
				moved.Revision++
				if err = t.SaveEntry(ctx, &entry, &moved, "PathMoved", commandID); err != nil {
					return nil, err
				}
				if entry.ID == old.ID {
					next = moved
				}
			}
		}
	}
	view, err := t.EntryView(next)
	if err != nil {
		return nil, err
	}
	result := &PathResult{Entry: view, Changed: changed}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	event, err := t.Append(ctx, "NamespaceCommandCompleted", next.ID, map[string]any{"command_id": commandID, "request_key": key, "request_hash": meaning, "result": result, "protocol_session_id": t.Scope.SessionID})
	if err != nil {
		return nil, err
	}
	if _, err = t.Tx.Exec(ctx, `INSERT INTO namespace_commands(tenant_id,partner_id,actor_id,request_key,request_hash,result,completed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, key, meaning, resultBytes, event); err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (t *Transaction) EntryView(e PathEntry) (PathEntry, error) {
	var err error
	e.Path, err = vpath.Relative(t.Root, e.Path)
	if err != nil {
		return e, err
	}
	e.Parent = vpath.Parent(e.Path)
	return e, nil
}

func (t *Transaction) FileAccessible(ctx context.Context, id string) error {
	return t.FileAccessibleMode(ctx, id, 4)
}

func (t *Transaction) FileAccessibleMode(ctx context.Context, id string, mask uint32) error {
	if t.Has("admin") && t.Root == "/" {
		return nil
	}
	var ownRaw bool
	if t.Root == "/" {
		err := t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) WHERE f.file_id=$1 AND e.actor_id=$2 AND NOT EXISTS(SELECT 1 FROM namespace_revisions v WHERE v.file_id=f.file_id))`, id, t.Actor).Scan(&ownRaw)
		if err != nil {
			return err
		}
		if ownRaw {
			return nil
		}
	}
	rows, err := t.Tx.Query(ctx, "SELECT "+entryColumns+entryJoin+` WHERE NOT n.deleted AND EXISTS(SELECT 1 FROM namespace_revisions v WHERE v.entry_id=n.entry_id AND v.file_id=$1) ORDER BY n.path LIMIT 1001`, id)
	if err != nil {
		return err
	}
	entries := make([]PathEntry, 0)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			rows.Close()
			return err
		}
		entries = append(entries, *e)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	if len(entries) > 1000 {
		return ErrLimit
	}
	for _, e := range entries {
		if !vpath.Within(t.Root, e.Path) {
			continue
		}
		if err = t.CheckAncestors(ctx, e.Path); err != nil {
			if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
				continue
			}
			return err
		}
		if err = t.EntryMode(&e, mask); err == nil {
			return nil
		}
	}
	return ErrNotFound
}

func (t *Transaction) ListEntries(ctx context.Context, actual, after string, limit int) ([]PathEntry, bool, error) {
	if err := t.Require("list"); err != nil {
		return nil, false, err
	}
	if limit < 1 || limit > 1000 {
		return nil, false, ErrLimit
	}
	if err := t.CheckAncestors(ctx, actual); err != nil {
		return nil, false, err
	}
	dir, err := t.Entry(ctx, actual)
	if err != nil {
		return nil, false, err
	}
	if dir.Kind != "dir" {
		return nil, false, ErrState
	}
	if err = t.EntryMode(dir, 5); err != nil {
		return nil, false, err
	}
	if after != "" && vpath.Parent(after) != actual {
		return nil, false, vpath.ErrPath
	}
	rows, err := t.Tx.Query(ctx, "SELECT "+entryColumns+entryJoin+` WHERE n.parent_path=$1 AND n.path>$2 AND NOT n.deleted ORDER BY n.path LIMIT $3`, actual, after, limit+1)
	if err != nil {
		return nil, false, err
	}
	result := make([]PathEntry, 0)
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			rows.Close()
			return nil, false, err
		}
		result = append(result, *e)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(result) > limit
	if more {
		result = result[:limit]
	}
	return result, more, nil
}
