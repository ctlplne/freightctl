package workflow

import (
	"context"
	"strings"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const ScheduledCollectionContract = "immutable-files-sha256-scheduled-manifest-v1"
const collectionDueToken = "{due_utc}"
const maxArrivalProbes = 65536

// Waiting for a producer is distinct from retrying a verified byte transfer.
// Its bounded probes never consume the collection worker's eight attempts.
type ScheduleArrivalSelection struct {
	LateAfter int `json:"late_after_seconds"`
	Deadline  int `json:"arrival_deadline_seconds"`
	Poll      int `json:"poll_interval_seconds"`
}

func (s *Service) stageScheduleArrival(ctx context.Context, t *store.Transaction, record *store.Schedule, d *ScheduleDefinition, o *store.ScheduleOccurrence, now time.Time) error {
	if d.Collection == nil {
		return ErrInput
	}
	name, err := collectionManifestName(d.Collection.Source, o.Due)
	if err != nil {
		return err
	}
	binding := ScheduleArrivalBinding{Schema: 1, Schedule: Reference{ID: record.ID, Version: record.Version, Hash: record.Hash}, OccurrenceID: o.ID, Due: o.Due, LateAfter: o.Due.Add(time.Duration(d.Collection.Arrival.LateAfter) * time.Second), ArrivalDeadline: o.Due.Add(time.Duration(d.Collection.Arrival.Deadline) * time.Second), Deadline: o.Deadline, Manifest: name}
	encoded, hash, err := digest(binding)
	if err != nil {
		return err
	}
	a := &store.ScheduleArrival{ID: o.ID, ScheduleID: record.ID, Version: record.Version, Definition: encoded, Hash: hash, State: "waiting", Revision: 1, Next: o.Due, Reason: "awaiting_expected_ready_manifest"}
	if !binding.ArrivalDeadline.After(now) {
		a.State = "missing"
		a.Reason = "arrival_window_elapsed_before_admission"
	}
	return t.SaveScheduleArrival(ctx, a, 0)
}
func arrivalBinding(a *store.ScheduleArrival) (*ScheduleArrivalBinding, error) {
	var d ScheduleArrivalBinding
	if Decode(a.Definition, &d) != nil || d.Schema != 1 || d.OccurrenceID != a.ID || d.Schedule.ID != a.ScheduleID || d.Schedule.Version != a.Version || !hashPattern.MatchString(d.Schedule.Hash) || !store.ValidID(d.OccurrenceID) || d.Due.IsZero() || d.Due.Nanosecond() != 0 || d.LateAfter.Before(d.Due) || !d.ArrivalDeadline.After(d.LateAfter) || !d.Deadline.After(d.ArrivalDeadline) || !collectionManifestPattern(CollectionContract, d.Manifest) {
		return nil, store.ErrIsolation
	}
	_, hash, err := digest(d)
	if err != nil || hash != a.Hash {
		return nil, store.ErrIsolation
	}
	return &d, nil
}

// Admission consumes the already observed manifest. It makes no peer contact
// while waiting for ordinary collection capacity.
func (s *Service) admitScheduleArrival(ctx context.Context, t *store.Transaction, a *store.ScheduleArrival) (*store.CollectionJob, error) {
	binding, err := arrivalBinding(a)
	if err != nil {
		return nil, err
	}
	if a.State != "ready" || a.ManifestHash == nil || a.Observed == nil || len(a.Manifest) == 0 {
		return nil, store.ErrState
	}
	record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
	if err != nil {
		return nil, err
	}
	d, _, err := scheduleDefinition(record)
	if err != nil {
		return nil, err
	}
	if err = s.checkArrivalCurrent(ctx, t, a, record, d); err != nil {
		return nil, err
	}
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, err
	}
	if !binding.Deadline.After(now) {
		return nil, store.ErrSchedule
	}
	if err = t.CollectionLock(ctx, true); err != nil {
		return nil, err
	}
	if err = t.CollectionAdmission(ctx, d.Workflow.ID); err != nil {
		return nil, err
	}
	source := d.Collection.Source
	frozen := CollectionDefinition{Schema: 1, Workflow: d.Workflow, Source: source, Connection: d.Collection.Connection, SourceIdentity: collectionSourceIdentity(d.Collection.Connection), Authority: d.Authority, StorageID: d.StorageID, Root: d.Root, Timeout: d.Deadline, Effects: d.Effects, Schedule: &CollectionScheduleBinding{Schedule: binding.Schedule, OccurrenceID: a.ID, Due: binding.Due, ArrivalDeadline: binding.ArrivalDeadline, Deadline: binding.Deadline, ManifestName: binding.Manifest, ManifestHash: *a.ManifestHash}}
	encoded, hash, err := digest(frozen)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 24<<10 {
		return nil, store.ErrLimit
	}
	job := &store.CollectionJob{ID: secure.NewID(), WorkflowID: d.Workflow.ID, WorkflowVersion: d.Workflow.Version, WorkflowHash: d.Workflow.Hash, Definition: encoded, Hash: hash, State: "queued", Revision: 1, Next: now, Created: now, Deadline: binding.Deadline, Reason: "awaiting_collection_worker"}
	if err = t.SaveCollection(ctx, job, 0); err != nil {
		return nil, err
	}
	previous := a.Revision
	a.Revision++
	a.State = "admitted"
	a.JobID = &job.ID
	a.Reason = "ready_manifest_queued_for_collection"
	if err = t.SaveScheduleArrival(ctx, a, previous); err != nil {
		return nil, err
	}
	return job, nil
}
func (s *Service) checkArrivalCurrent(ctx context.Context, t *store.Transaction, a *store.ScheduleArrival, record *store.Schedule, d *ScheduleDefinition) error {
	if d.Collection == nil || record.State != "active" || record.ApprovalAuthority != t.AuthorityRevision || d.Authority != t.AuthorityRevision {
		return store.ErrSchedule
	}
	if err := tRequireArrival(t, d); err != nil {
		return err
	}
	_, w, err := approved(ctx, t, d.Workflow)
	if err != nil {
		return err
	}
	if err = checkScheduleEffects(ctx, t, d, w); err != nil {
		return err
	}
	if err = s.checkStorage(d.StorageID); err != nil {
		return err
	}
	if d.Collection.Source.MaxFile > s.Custody.MaxFile || d.Collection.Source.MaxTotal > s.Custody.MaxStored {
		return store.ErrLimit
	}
	var current bool
	if err = t.Tx.QueryRow(ctx, `SELECT freightctl_arrival_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, a.Definition).Scan(&current); err != nil {
		return err
	}
	if !current {
		return store.ErrSchedule
	}
	return nil
}
func tRequireArrival(t *store.Transaction, d *ScheduleDefinition) error {
	for _, grant := range []string{"workflow_execute", "read", "write", "list"} {
		if err := t.Require(grant); err != nil {
			return err
		}
	}
	if len(d.Effects) > 0 {
		return t.Require("deliver")
	}
	return nil
}
func (s *Service) scheduledCollectionManifest(ctx context.Context, scope store.Scope, d *CollectionDefinition) (*CollectionManifest, string, error) {
	if d.Schedule == nil {
		return nil, "", ErrInput
	}
	t, err := s.collectionRead(ctx, scope)
	if err != nil {
		return nil, "", err
	}
	defer t.Tx.Rollback(ctx)
	a, err := t.ScheduleArrival(ctx, d.Schedule.OccurrenceID, false)
	if err != nil {
		return nil, "", err
	}
	if a.State != "admitted" || a.ManifestHash == nil || *a.ManifestHash != d.Schedule.ManifestHash {
		return nil, "", store.ErrCollection
	}
	manifest, hash, err := parseCollectionManifest(a.Manifest, d.Source)
	if err != nil {
		return nil, "", err
	}
	if hash != d.Schedule.ManifestHash {
		return nil, "", store.ErrCollection
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return manifest, hash, nil
}

func validateCollectionSchedule(j *store.CollectionJob, d *CollectionDefinition) error {
	if d.Schedule == nil {
		if d.Source.Contract != CollectionContract || d.Timeout > 3600 {
			return store.ErrState
		}
		return nil
	}
	b := d.Schedule
	name, err := collectionManifestName(d.Source, b.Due)
	if err != nil || !store.ValidID(b.Schedule.ID) || b.Schedule.Version < 1 || !hashPattern.MatchString(b.Schedule.Hash) || !store.ValidID(b.OccurrenceID) || b.ManifestName != name || !hashPattern.MatchString(b.ManifestHash) || !b.ArrivalDeadline.After(b.Due) || !b.Deadline.After(b.ArrivalDeadline) || b.Deadline.Sub(b.Due) != time.Duration(d.Timeout)*time.Second || !j.Deadline.Equal(b.Deadline) || j.Created.Before(b.Due) {
		return store.ErrState
	}
	return nil
}

type ScheduleCollection struct {
	Source     CollectionSource         `json:"source"`
	Connection ConnectionView           `json:"source_connection"`
	Arrival    ScheduleArrivalSelection `json:"arrival"`
}
type CollectionScheduleBinding struct {
	Schedule        Reference `json:"schedule"`
	OccurrenceID    string    `json:"occurrence_id"`
	Due             time.Time `json:"due_at"`
	ArrivalDeadline time.Time `json:"arrival_deadline_at"`
	Deadline        time.Time `json:"deadline_at"`
	ManifestName    string    `json:"manifest_name"`
	ManifestHash    string    `json:"manifest_hash"`
}

type ScheduleArrivalBinding struct {
	Schema          int       `json:"schema_version"`
	Schedule        Reference `json:"schedule"`
	OccurrenceID    string    `json:"occurrence_id"`
	Due             time.Time `json:"due_at"`
	LateAfter       time.Time `json:"late_after_at"`
	ArrivalDeadline time.Time `json:"arrival_deadline_at"`
	Deadline        time.Time `json:"deadline_at"`
	Manifest        string    `json:"manifest_name"`
}

func collectionManifestPattern(contract, name string) bool {
	if contract == ScheduledCollectionContract {
		if strings.Count(name, collectionDueToken) != 1 {
			return false
		}
		name = strings.ReplaceAll(name, collectionDueToken, "20060102T150405Z")
	} else if contract != CollectionContract {
		return false
	}
	return filenamePattern.MatchString(name) && strings.HasSuffix(name, ".ready.json")
}
func collectionManifestName(source CollectionSource, due time.Time) (string, error) {
	if source.Contract != ScheduledCollectionContract || normalizeCollectionSource(source) != nil || due.IsZero() || due.UTC().Year() < 1 || due.UTC().Year() > 9999 || due.Nanosecond() != 0 {
		return "", ErrInput
	}
	name := strings.ReplaceAll(source.Manifest, collectionDueToken, due.UTC().Format("20060102T150405Z"))
	if !filenamePattern.MatchString(name) {
		return "", ErrInput
	}
	return name, nil
}
func normalizeScheduleArrival(a ScheduleArrivalSelection, execution int) error {
	if a.LateAfter < 0 || a.Deadline <= a.LateAfter || a.Deadline >= execution || a.Poll < 1 || a.Poll > 3600 || a.Poll > a.Deadline || (a.Deadline+a.Poll-1)/a.Poll+1 > maxArrivalProbes {
		return ErrInput
	}
	return nil
}
func validScheduleSource(source ScheduleSourceSelection) bool {
	if source.Kind == "" || source.Kind == ProcessingScheduleSource {
		return schedulePattern.MatchString(source.Pattern)
	}
	return source.Kind != "webdav.collect" && collectionSourceKind(source.Kind) && !source.Recursive && collectionManifestPattern(ScheduledCollectionContract, source.Pattern)
}
func (s *Service) scheduleCollection(ctx context.Context, t *store.Transaction, x ScheduleSelection, w *Definition) (*ScheduleCollection, error) {
	if w.Schema == 3 {
		if x.Arrival != nil {
			return nil, ErrInput
		}
		if _, err := processingScheduleBinding(w, x.Source); err != nil {
			return nil, err
		}
		if err := processingScheduleGrants(t); err != nil {
			return nil, err
		}
		return nil, scheduleDirectory(ctx, t, x.Source.Directory)
	}
	if x.Source.Kind == "" {
		if w.Source != nil || x.Arrival != nil {
			return nil, ErrInput
		}
		if err := t.Require("deliver"); err != nil {
			return nil, err
		}
		return nil, scheduleDirectory(ctx, t, x.Source.Directory)
	}
	if w.Source == nil || w.Source.Kind != x.Source.Kind || w.Source.Contract != ScheduledCollectionContract || x.Arrival == nil || x.Source.Directory != w.Source.Directory || x.Source.Pattern != w.Source.Manifest || x.MaxFiles != w.Source.MaxFiles {
		return nil, ErrInput
	}
	if len(w.Steps) > 0 {
		if err := t.Require("deliver"); err != nil {
			return nil, err
		}
	}
	if w.Source.MaxFile > s.Custody.MaxFile || w.Source.MaxTotal > s.Custody.MaxStored {
		return nil, store.ErrLimit
	}
	_, connection, err := collectionConnection(ctx, t, w.Source)
	if err != nil {
		return nil, err
	}
	return &ScheduleCollection{Source: *w.Source, Connection: *connection, Arrival: *x.Arrival}, nil
}
