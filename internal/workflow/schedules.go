package workflow

import (
	"context"
	"errors"
	"path"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
	"golang.org/x/text/unicode/norm"
)

type ScheduleSourceSelection struct {
	Directory string `json:"directory"`
	Pattern   string `json:"filename_pattern"`
	Recursive bool   `json:"recursive"`
	Kind      string `json:"kind,omitempty"`
}
type ScheduleSource struct {
	ScheduleSourceSelection
	Regex string `json:"filename_regex"`
}
type ScheduleSelection struct {
	Name              string                    `json:"name"`
	Workflow          Reference                 `json:"workflow"`
	Source            ScheduleSourceSelection   `json:"source"`
	Calendar          calendar.Selection        `json:"calendar"`
	Missed            string                    `json:"missed_run_policy"`
	CatchUp           int                       `json:"max_catch_up"`
	MaxActive         int                       `json:"max_active_runs"`
	MaxFiles          int                       `json:"max_files_per_occurrence"`
	Deadline          int                       `json:"execution_deadline_seconds"`
	Grace             int                       `json:"late_start_grace_seconds"`
	ExpectedAuthority int64                     `json:"expected_authority_revision"`
	Arrival           *ScheduleArrivalSelection `json:"arrival,omitempty"`
}
type ScheduleDefinition struct {
	Schema     int                  `json:"schema_version"`
	Name       string               `json:"name"`
	Workflow   Reference            `json:"workflow"`
	Source     ScheduleSource       `json:"source"`
	Calendar   calendar.Definition  `json:"calendar"`
	Missed     string               `json:"missed_run_policy"`
	CatchUp    int                  `json:"max_catch_up"`
	MaxActive  int                  `json:"max_active_runs"`
	MaxFiles   int                  `json:"max_files_per_occurrence"`
	Deadline   int                  `json:"execution_deadline_seconds"`
	Grace      int                  `json:"late_start_grace_seconds"`
	Authority  int64                `json:"authority_revision"`
	StorageID  string               `json:"storage_id"`
	Root       string               `json:"namespace_root"`
	Effects    []Effect             `json:"effects"`
	Collection *ScheduleCollection  `json:"collection,omitempty"`
	Processing *ScheduledProcessing `json:"processing,omitempty"`
}
type SchedulePreview struct {
	Definition       ScheduleDefinition    `json:"definition"`
	Hash             string                `json:"definition_hash"`
	FirstDue         *time.Time            `json:"first_due"`
	LatestDue        *time.Time            `json:"latest_due"`
	Upcoming         []calendar.Occurrence `json:"upcoming"`
	Effects          []Effect              `json:"effects"`
	ExternalContact  bool                  `json:"external_contact"`
	ApprovalRequired bool                  `json:"approval_required"`
}
type ScheduleDraftRequest struct {
	ID              string            `json:"schedule_id,omitempty"`
	ExpectedVersion int               `json:"expected_version"`
	Selection       ScheduleSelection `json:"selection"`
	Hash            string            `json:"definition_hash"`
}
type ScheduleResource struct {
	Kind     string                `json:"kind"`
	Schedule store.ScheduleSummary `json:"schedule"`
	Profile  string                `json:"profile,omitempty"`
}
type ScheduleView struct {
	Schedule         *store.Schedule       `json:"schedule"`
	Upcoming         []calendar.Occurrence `json:"upcoming"`
	Pending          []string              `json:"pending_runs"`
	ActiveRuns       int                   `json:"active_runs"`
	CurrentAuthority bool                  `json:"current_authority"`
	PendingArrivals  []string              `json:"pending_arrivals,omitempty"`
}

var schedulePattern = regexp.MustCompile(`^[A-Za-z0-9._*?-]{1,128}$`)

func scheduleRegex(pattern string) string {
	return "^" + strings.NewReplacer(".", "[.]", "*", ".*", "?", ".").Replace(pattern) + "$"
}
func normalizeScheduleSelection(x ScheduleSelection) (ScheduleSelection, error) {
	x.Name = norm.NFC.String(x.Name)
	if !utf8.ValidString(x.Name) || len(x.Name) < 1 || len(x.Name) > 256 || x.ExpectedAuthority < 1 || !store.ValidID(x.Workflow.ID) || x.Workflow.Version < 1 || !hashPattern.MatchString(x.Workflow.Hash) || !validScheduleSource(x.Source) || x.CatchUp < 1 || x.CatchUp > 100 || x.MaxActive < 1 || x.MaxActive > 64 || x.MaxFiles < 1 || x.MaxFiles > 64 || x.Deadline < 1 || x.Deadline > 604800 || x.Grace < 1 || x.Grace > 3600 || x.Grace > x.Deadline || (x.Missed != "skip" && x.Missed != "latest" && x.Missed != "all") {
		return x, ErrInput
	}
	for _, r := range x.Name {
		if unicode.IsControl(r) {
			return x, ErrInput
		}
	}
	p, e := vpath.Canonical(x.Source.Directory)
	if e != nil || p != x.Source.Directory || vpath.ControlPath(p) {
		return x, ErrInput
	}
	if collectionSourceKind(x.Source.Kind) != (x.Arrival != nil) {
		return x, ErrInput
	}
	if x.Arrival != nil && normalizeScheduleArrival(*x.Arrival, x.Deadline) != nil {
		return x, ErrInput
	}
	x.Calendar, e = calendar.Normalize(x.Calendar)
	if e != nil {
		return x, ErrInput
	}
	return x, nil
}
func (s *Service) scheduleBegin(ctx context.Context, scope store.Scope, grants ...string) (*store.Transaction, error) {
	t, e := s.Custody.DB.BeginApproval(ctx, scope)
	if e != nil {
		return nil, e
	}
	if t.Root != "/" {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	for _, g := range grants {
		if e = t.Require(g); e != nil {
			t.Tx.Rollback(ctx)
			return nil, e
		}
	}
	if e = t.ScheduleLock(ctx, true); e != nil {
		t.Tx.Rollback(ctx)
		return nil, e
	}
	return t, nil
}
func (s *Service) scheduleRead(ctx context.Context, scope store.Scope) (*store.Transaction, error) {
	t, e := s.begin(ctx, scope)
	if e != nil {
		return nil, e
	}
	if !t.Has("workflow_manage") && !t.Has("workflow_approve") && !t.Has("workflow_execute") {
		t.Tx.Rollback(ctx)
		return nil, store.ErrForbidden
	}
	return t, nil
}
func scheduleDirectory(ctx context.Context, t *store.Transaction, directory string) error {
	if e := t.CheckAncestors(ctx, path.Join(directory, "schedule-source")); e != nil {
		return e
	}
	entry, e := t.Entry(ctx, directory)
	if e != nil {
		return e
	}
	if entry.Kind != "dir" {
		return store.ErrState
	}
	return t.EntryMode(entry, 5)
}
func (s *Service) schedulePreview(ctx context.Context, t *store.Transaction, x ScheduleSelection) (*SchedulePreview, error) {
	x, e := normalizeScheduleSelection(x)
	if e != nil {
		return nil, e
	}
	if x.ExpectedAuthority != t.AuthorityRevision {
		return nil, store.ErrRevision
	}
	for _, g := range []string{"list", "read"} {
		if e = t.Require(g); e != nil {
			return nil, e
		}
	}
	_, workflow, e := approved(ctx, t, x.Workflow)
	if e != nil {
		return nil, e
	}
	processing, e := processingScheduleBinding(workflow, x.Source)
	if e != nil {
		return nil, e
	}
	if processing != nil && s.Processor == nil {
		return nil, store.ErrState
	}
	collection, e := s.scheduleCollection(ctx, t, x, workflow)
	if e != nil {
		return nil, e
	}
	if s.Custody.Disk == nil {
		return nil, custody.ErrStorageIdentity
	}
	storage := s.Custody.Disk.Identity()
	if e = s.checkStorage(storage); e != nil {
		return nil, e
	}
	rules, e := calendar.Snapshot(x.Calendar)
	if e != nil {
		return nil, ErrInput
	}
	d := ScheduleDefinition{Schema: 1, Name: x.Name, Workflow: x.Workflow, Source: ScheduleSource{ScheduleSourceSelection: x.Source, Regex: scheduleRegex(x.Source.Pattern)}, Calendar: rules, Missed: x.Missed, CatchUp: x.CatchUp, MaxActive: x.MaxActive, MaxFiles: x.MaxFiles, Deadline: x.Deadline, Grace: x.Grace, Authority: t.AuthorityRevision, StorageID: storage, Root: t.Root}
	d.Collection = collection
	if processing != nil {
		d.Schema, d.Processing = 2, processing
	}
	if collection != nil {
		d.Source.Regex = ""
	}
	p, _ := calendar.Compile(rules)
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	upcoming, e := p.Preview(now.Add(-time.Nanosecond), 12)
	if e != nil {
		return nil, e
	}
	out := &SchedulePreview{Definition: d, FirstDue: p.Next(d.Calendar.Start.Add(-time.Nanosecond)), LatestDue: p.Previous(now.Add(time.Nanosecond)), Upcoming: upcoming, Effects: []Effect{}, ApprovalRequired: true}
	effects, e := workflowEffects(ctx, t, workflow)
	if e != nil {
		return nil, e
	}
	out.Effects = effects
	out.Definition.Effects = effects
	encoded, hash, e := digest(out.Definition)
	if e != nil {
		return nil, e
	}
	if len(encoded) > 24<<10 {
		return nil, store.ErrLimit
	}
	out.Hash = hash
	return out, nil
}
func (s *Service) PreviewSchedule(ctx context.Context, scope store.Scope, x ScheduleSelection) (*SchedulePreview, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := s.schedulePreview(ctx, t, x)
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}
func scheduleDefinition(s *store.Schedule) (*ScheduleDefinition, *calendar.Plan, error) {
	var d ScheduleDefinition
	if Decode(s.Definition, &d) != nil || (d.Schema != 1 && d.Schema != 2) || (d.Schema == 2) != (d.Processing != nil) || d.Name != s.Name || d.Root != "/" || !store.ValidID(d.StorageID) || d.Authority < 1 {
		return nil, nil, store.ErrIsolation
	}
	_, h, e := digest(d)
	if e != nil || h != s.Hash {
		return nil, nil, store.ErrIsolation
	}
	x := ScheduleSelection{Name: d.Name, Workflow: d.Workflow, Source: d.Source.ScheduleSourceSelection, Calendar: d.Calendar.Selection, Missed: d.Missed, CatchUp: d.CatchUp, MaxActive: d.MaxActive, MaxFiles: d.MaxFiles, Deadline: d.Deadline, Grace: d.Grace, ExpectedAuthority: d.Authority}
	expectedRegex := scheduleRegex(d.Source.Pattern)
	if d.Collection != nil {
		x.Arrival = &d.Collection.Arrival
		expectedRegex = ""
		if d.Collection.Source.Contract != ScheduledCollectionContract || normalizeCollectionSource(d.Collection.Source) != nil || d.Source.Directory != d.Collection.Source.Directory || d.Source.Pattern != d.Collection.Source.Manifest || d.MaxFiles != d.Collection.Source.MaxFiles {
			return nil, nil, store.ErrIsolation
		}
	}
	if d.Processing != nil {
		if checkProcessingSchedule(&d, &Definition{Schema: 3, Name: "Scheduled task shape", Processing: &d.Processing.Task}) != nil {
			return nil, nil, store.ErrIsolation
		}
	} else if d.Source.Kind == ProcessingScheduleSource {
		return nil, nil, store.ErrIsolation
	}
	if _, e = normalizeScheduleSelection(x); e != nil || d.Source.Regex != expectedRegex {
		return nil, nil, store.ErrIsolation
	}
	p, e := calendar.Compile(d.Calendar)
	if e != nil {
		return nil, nil, store.ErrIsolation
	}
	return &d, p, nil
}
func (s *Service) DraftSchedule(ctx context.Context, scope store.Scope, key string, x ScheduleDraftRequest) (*Result, error) {
	if !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || (x.ID == "" && x.ExpectedVersion != 0) || (x.ID != "" && (!store.ValidID(x.ID) || x.ExpectedVersion < 1)) {
		return nil, ErrInput
	}
	if _, e := normalizeScheduleSelection(x.Selection); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleBegin(ctx, scope, "workflow_manage", "list", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, e := digest(struct {
		Kind  string
		Input ScheduleDraftRequest
	}{"schedule_draft", x})
	if e != nil {
		return nil, e
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	preview, e := s.schedulePreview(ctx, t, x.Selection)
	if e != nil {
		return nil, e
	}
	if preview.Hash != x.Hash {
		return nil, store.ErrRevision
	}
	id := x.ID
	if id == "" {
		id = secure.NewID()
	}
	n, e := t.ScheduleVersion(ctx, id)
	if e != nil {
		return nil, e
	}
	if n != x.ExpectedVersion {
		return nil, store.ErrRevision
	}
	var live int
	if e = t.Tx.QueryRow(ctx, `SELECT count(*) FROM workflow_schedules WHERE actor_id=$1 AND state IN ('draft','active','suspended')`, t.Actor).Scan(&live); e != nil {
		return nil, e
	}
	if live >= 128 {
		return nil, store.ErrLimit
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	data, _, e := digest(preview.Definition)
	if e != nil {
		return nil, e
	}
	record := &store.Schedule{ScheduleSummary: store.ScheduleSummary{ID: id, Version: n + 1, Name: preview.Definition.Name, Hash: preview.Hash, State: "draft", Revision: 1, CreatedAt: now}, Definition: data}
	if e = t.SaveSchedule(ctx, record, 0); e != nil {
		return nil, e
	}
	return scheduleResult(t, ctx, key, meaning, id, processingScheduleResource(record, preview.Definition.Processing))
}
func (s *Service) ControlSchedule(ctx context.Context, scope store.Scope, id string, version int, action, key string, x Decision) (*Result, error) {
	if !store.ValidID(id) || version < 1 || !keyPattern.MatchString(key) || !hashPattern.MatchString(x.Hash) || x.Revision < 1 || (action != "activate" && action != "suspend" && action != "revoke") {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleBegin(ctx, scope, "workflow_approve")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, e := digest(struct {
		Kind, ID, Action string
		Version          int
		Decision         Decision
	}{"schedule_control", id, action, version, x})
	if e != nil {
		return nil, e
	}
	if prior, e := replay(t, ctx, key, meaning); e != nil || prior != nil {
		return prior, e
	}
	record, e := t.Schedule(ctx, id, version, true)
	if e != nil {
		return nil, e
	}
	d, p, e := scheduleDefinition(record)
	if e != nil {
		return nil, e
	}
	if record.Hash != x.Hash || record.Revision != x.Revision {
		return nil, store.ErrRevision
	}
	previous := record.Revision
	if action == "activate" {
		if record.State != "draft" && record.State != "suspended" {
			return nil, store.ErrState
		}
		for _, g := range []string{"workflow_execute", "list", "read"} {
			if e = t.Require(g); e != nil {
				return nil, e
			}
		}
		n, e := t.ScheduleVersion(ctx, id)
		if e != nil {
			return nil, e
		}
		if n != version || d.Authority != t.AuthorityRevision {
			return nil, store.ErrRevision
		}
		_, workflow, e := approved(ctx, t, d.Workflow)
		if e != nil {
			return nil, e
		}
		if e = checkScheduleEffects(ctx, t, d, workflow); e != nil {
			return nil, e
		}
		if d.Collection == nil {
			if e = scheduleDirectory(ctx, t, d.Source.Directory); e != nil {
				return nil, e
			}
		}
		if e = s.checkStorage(d.StorageID); e != nil {
			return nil, e
		}
		rows, e := t.Tx.Query(ctx, `SELECT version FROM workflow_schedules WHERE schedule_id=$1 AND state='active' AND version<>$2`, id, version)
		if e != nil {
			return nil, e
		}
		versions := []int{}
		for rows.Next() {
			var v int
			if e = rows.Scan(&v); e != nil {
				rows.Close()
				return nil, e
			}
			versions = append(versions, v)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		for _, v := range versions {
			old, e := t.Schedule(ctx, id, v, true)
			if e != nil {
				return nil, e
			}
			before := old.Revision
			old.State = "suspended"
			old.Revision++
			if e = t.SaveSchedule(ctx, old, before); e != nil {
				return nil, e
			}
		}
		if record.State == "draft" {
			record.NextDue = p.Next(d.Calendar.Start.Add(-time.Nanosecond))
		}
		record.State = "active"
		record.ApprovalAuthority = t.AuthorityRevision
	} else {
		if record.State == "revoked" || (action == "suspend" && record.State != "active") {
			return nil, store.ErrState
		}
		if action == "suspend" {
			record.State = "suspended"
		} else {
			record.State = "revoked"
		}
	}
	record.Revision++
	if e = t.SaveSchedule(ctx, record, previous); e != nil {
		return nil, e
	}
	return scheduleResult(t, ctx, key, meaning, id, processingScheduleResource(record, d.Processing))
}
func (s *Service) ScheduleStatus(ctx context.Context, scope store.Scope, id string, version int) (*ScheduleView, error) {
	if !store.ValidID(id) || version < 1 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	if e = t.ScheduleLock(ctx, false); e != nil {
		return nil, e
	}
	record, e := t.Schedule(ctx, id, version, false)
	if e != nil {
		return nil, e
	}
	d, p, e := scheduleDefinition(record)
	if e != nil {
		return nil, e
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	upcoming, e := p.Preview(now.Add(-time.Nanosecond), 12)
	if e != nil {
		return nil, e
	}
	pending, e := t.SchedulePending(ctx, id, version, 64)
	if e != nil {
		return nil, e
	}
	active, e := t.ScheduleActiveRuns(ctx, id)
	var arrivals []string
	if d.Collection != nil {
		active, e = t.ScheduleCollectionActive(ctx, id)
		if e != nil {
			return nil, e
		}
		arrivals, e = t.ScheduleArrivalPending(ctx, id, version)
	}
	if e != nil {
		return nil, e
	}
	current := record.State == "active" && record.ApprovalAuthority == t.AuthorityRevision && d.Authority == t.AuthorityRevision
	if current && d.Processing != nil {
		_, w, err := approved(ctx, t, d.Workflow)
		if err == nil {
			err = checkScheduleEffects(ctx, t, d, w)
		}
		if err == nil {
			err = scheduleDirectory(ctx, t, d.Source.Directory)
		}
		if err != nil {
			if !errors.Is(err, store.ErrState) && !errors.Is(err, store.ErrRevision) && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrSchedule) {
				return nil, err
			}
			current = false
		}
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return &ScheduleView{Schedule: record, Upcoming: upcoming, Pending: pending, PendingArrivals: arrivals, ActiveRuns: active, CurrentAuthority: current}, t.Tx.Commit(ctx)
}
func (s *Service) Schedules(ctx context.Context, scope store.Scope, after string, limit int) (*store.SchedulePage, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := t.Schedules(ctx, after, limit)
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ScheduleHistory(ctx context.Context, scope store.Scope, id, after string, limit int) (*store.ScheduleHistory, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := t.ScheduleHistory(ctx, id, after, limit)
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}
func (s *Service) ScheduleOccurrence(ctx context.Context, scope store.Scope, id string) (*store.ScheduleOccurrenceView, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	p, e := t.ScheduleOccurrence(ctx, id)
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return p, t.Tx.Commit(ctx)
}

// Keep authorization failures explicit; the worker can wait for a named review,
// but cannot grant it or turn a stale schedule into current authority.
func ScheduleWait(err error) bool {
	return errors.Is(err, store.ErrDispatchApproval) || errors.Is(err, store.ErrSchedule) || errors.Is(err, store.ErrArrival) || errors.Is(err, store.ErrCollection) || errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrState) || errors.Is(err, store.ErrLimit)
}

// Return the stored receipt on the first response as well as every replay.
// PostgreSQL JSON encoding must not produce two different receipt byte strings.
func scheduleResult(t *store.Transaction, ctx context.Context, key, meaning, id string, value any) (*Result, error) {
	if e := t.WorkflowReceipt(ctx, key, meaning, id, value); e != nil {
		return nil, e
	}
	data, e := t.WorkflowReplay(ctx, key, meaning)
	if e != nil {
		return nil, e
	}
	if len(data) == 0 {
		return nil, store.ErrIsolation
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return &Result{Resource: data}, t.Tx.Commit(ctx)
}

func workflowEffects(ctx context.Context, t *store.Transaction, workflow *Definition) ([]Effect, error) {
	effects := []Effect{}
	views, e := connections(ctx, t, *workflow)
	if e != nil {
		return nil, e
	}
	for i, v := range views {
		step := workflow.Steps[i]
		effect := Effect{StepID: step.ID, Connection: step.Connection, Address: v.Address, Directory: v.Directory, FinalNamePattern: "<delivery UUID>-" + step.Filename, HostFingerprint: v.HostFingerprint, Encryption: step.Encryption}
		if v.FTPS != nil {
			effect.Protocol = "ftps"
			effect.User = v.User
			effect.FTPS = v.FTPS
		}
		if step.Encryption != nil {
			k, e := t.EncryptionKey(ctx, *step.Encryption)
			if e != nil {
				return nil, e
			}
			effect.RecipientFingerprint = k.Fingerprint
			effect.EncryptionFingerprint = k.Recipient.Fingerprint
		}
		effects = append(effects, effect)
	}
	return effects, nil
}
func checkScheduleEffects(ctx context.Context, t *store.Transaction, d *ScheduleDefinition, workflow *Definition) error {
	if d.Processing != nil {
		if err := checkProcessingSchedule(d, workflow); err != nil {
			return err
		}
		return processingScheduleGrants(t)
	}
	if workflow.Schema == 3 {
		return store.ErrSchedule
	}
	effects, e := workflowEffects(ctx, t, workflow)
	if e != nil {
		return e
	}
	if d.Collection == nil {
		if workflow.Source != nil || d.Source.Kind != "" {
			return store.ErrSchedule
		}
		if e = t.Require("deliver"); e != nil {
			return e
		}
	} else {
		if workflow.Source == nil || d.Source.Kind != workflow.Source.Kind || !collectionSourceKind(d.Source.Kind) || !reflect.DeepEqual(*workflow.Source, d.Collection.Source) {
			return store.ErrSchedule
		}
		_, connection, e := collectionConnection(ctx, t, workflow.Source)
		if e != nil {
			return e
		}
		if !reflect.DeepEqual(*connection, d.Collection.Connection) {
			return store.ErrSchedule
		}
		if len(workflow.Steps) > 0 {
			if e = t.Require("deliver"); e != nil {
				return e
			}
		}
	}
	if !reflect.DeepEqual(effects, d.Effects) {
		return store.ErrRevision
	}
	return nil
}

type SchedulableWorkflow struct {
	Reference
	Name       string               `json:"name"`
	Source     *CollectionSource    `json:"source,omitempty"`
	Processing *ScheduledProcessing `json:"processing,omitempty"`
}
type SchedulableWorkflowPage struct {
	Workflows []SchedulableWorkflow `json:"workflows"`
	Next      string                `json:"next,omitempty"`
}

func (s *Service) SchedulableWorkflows(ctx context.Context, scope store.Scope, after string, limit int) (*SchedulableWorkflowPage, error) {
	if (after != "" && !store.ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	rows, e := t.Tx.Query(ctx, `SELECT w.workflow_id::text,w.version,w.definition_hash,w.definition->>'name',w.definition->'source',w.definition FROM workflow_revisions w WHERE w.actor_id=$1 AND (NOT (w.definition ? 'source') OR w.definition->'source'->>'completion_contract'='immutable-files-sha256-scheduled-manifest-v1') AND w.state='approved' AND w.approval_authority=$2 AND ($3='' OR w.workflow_id>nullif($3,'')::uuid) AND w.version=(SELECT max(v.version) FROM workflow_revisions v WHERE v.actor_id=$1 AND v.workflow_id=w.workflow_id AND v.state='approved' AND v.approval_authority=$2) AND (w.definition->>'schema_version'<>'3' OR w.version=(SELECT max(latest.version) FROM workflow_revisions latest WHERE latest.actor_id=$1 AND latest.workflow_id=w.workflow_id)) ORDER BY w.workflow_id LIMIT $4`, t.Actor, t.AuthorityRevision, after, limit+1)
	if e != nil {
		return nil, e
	}
	out := &SchedulableWorkflowPage{Workflows: []SchedulableWorkflow{}}
	for rows.Next() {
		var w SchedulableWorkflow
		var source, raw []byte
		if e = rows.Scan(&w.ID, &w.Version, &w.Hash, &w.Name, &source, &raw); e != nil {
			rows.Close()
			return nil, e
		}
		if len(source) != 0 {
			w.Source = &CollectionSource{}
			if Decode(source, w.Source) != nil || normalizeCollectionSource(*w.Source) != nil || w.Source.Contract != ScheduledCollectionContract {
				rows.Close()
				return nil, store.ErrState
			}
		}
		var declared Definition
		if Decode(raw, &declared) != nil {
			rows.Close()
			return nil, store.ErrIsolation
		}
		if declared.Schema == 3 {
			normalized, err := Normalize(declared)
			if err != nil {
				rows.Close()
				return nil, err
			}
			_, hash, _ := digest(normalized)
			if hash != w.Hash {
				rows.Close()
				return nil, store.ErrIsolation
			}
			w.Processing, e = processingScheduleBinding(&normalized, ScheduleSourceSelection{Kind: ProcessingScheduleSource, Directory: "/", Pattern: "*"})
			if e != nil {
				rows.Close()
				return nil, e
			}
		}
		if len(out.Workflows) == limit {
			out.Next = out.Workflows[len(out.Workflows)-1].ID
			break
		}
		out.Workflows = append(out.Workflows, w)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	if e = t.Reauthorize(ctx); e != nil {
		return nil, e
	}
	return out, t.Tx.Commit(ctx)
}

func scheduleEffects(ctx context.Context, t *store.Transaction, workflow *Definition) ([]Effect, error) {
	if workflow.Source != nil {
		return nil, ErrInput
	}
	return workflowEffects(ctx, t, workflow)
}
