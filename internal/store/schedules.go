package store

import (
	"context"
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
	"time"
)

var ErrSchedule = errors.New("current schedule authority and execution deadline required")

type ScheduleSummary struct {
	ID                string     `json:"id"`
	Version           int        `json:"version"`
	Name              string     `json:"name"`
	Hash              string     `json:"definition_hash"`
	State             string     `json:"state"`
	Revision          int64      `json:"revision"`
	ApprovalAuthority int64      `json:"approval_authority"`
	NextDue           *time.Time `json:"next_due"`
	CreatedAt         time.Time  `json:"created_at"`
	EventID           string     `json:"changed_event_id"`
}
type Schedule struct {
	ScheduleSummary
	Definition json.RawMessage `json:"definition"`
}
type ScheduleListing struct {
	ScheduleSummary
	ActiveVersion int `json:"active_version"`
}
type SchedulePage struct {
	Schedules []ScheduleListing `json:"schedules"`
	Next      string            `json:"next,omitempty"`
}
type ScheduleOccurrence struct {
	ID           string     `json:"id"`
	ScheduleID   string     `json:"schedule_id"`
	Version      int        `json:"schedule_version"`
	Due          time.Time  `json:"due_at"`
	Deadline     time.Time  `json:"deadline_at"`
	Kind         string     `json:"kind"`
	SkippedUntil *time.Time `json:"skipped_until"`
	InputCount   int        `json:"input_count"`
	EventID      string     `json:"event_id"`
}
type ScheduleInput struct {
	ScheduleID   string `json:"schedule_id"`
	Version      int    `json:"schedule_version"`
	OccurrenceID string `json:"occurrence_id"`
	FileID       string `json:"file_id"`
	RunID        string `json:"run_id"`
	EventID      string `json:"event_id"`
}
type ScheduleOccurrenceView struct {
	ScheduleOccurrence
	Inputs  []ScheduleInput  `json:"inputs"`
	Arrival *ScheduleArrival `json:"arrival,omitempty"`
}
type ScheduleHistory struct {
	Occurrences []ScheduleOccurrence `json:"occurrences"`
	Next        string               `json:"next,omitempty"`
}

const scheduleColumns = `schedule_id::text,version,definition->>'name',definition_hash,state,revision,approval_authority,next_due,created_at,changed_event_id::text`

func scanSchedule(row pgx.Row, full bool, extra ...any) (*Schedule, error) {
	s := &Schedule{}
	args := []any{&s.ID, &s.Version, &s.Name, &s.Hash, &s.State, &s.Revision, &s.ApprovalAuthority, &s.NextDue, &s.CreatedAt, &s.EventID}
	if full {
		args = append(args, &s.Definition)
	}
	args = append(args, extra...)
	err := row.Scan(args...)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.CreatedAt = s.CreatedAt.UTC()
	if s.NextDue != nil {
		v := s.NextDue.UTC()
		s.NextDue = &v
	}
	return s, nil
}
func (t *Transaction) ScheduleLock(ctx context.Context, exclusive bool) error {
	fn := "pg_advisory_xact_lock_shared"
	if exclusive {
		fn = "pg_advisory_xact_lock"
	}
	_, e := t.Tx.Exec(ctx, `SELECT `+fn+`(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":workflow-schedules")
	return e
}
func (t *Transaction) Schedule(ctx context.Context, id string, version int, lock bool) (*Schedule, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	q := `SELECT ` + scheduleColumns + `,definition FROM workflow_schedules WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND schedule_id=$4 AND version=$5`
	if lock {
		q += ` FOR UPDATE`
	}
	return scanSchedule(t.Tx.QueryRow(ctx, q, t.Scope.Tenant, t.Scope.Partner, t.Actor, id, version), true)
}
func (t *Transaction) ScheduleVersion(ctx context.Context, id string) (int, error) {
	var n int
	e := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM workflow_schedules WHERE schedule_id=$1 AND actor_id=$2`, id, t.Actor).Scan(&n)
	return n, e
}
func (t *Transaction) SaveSchedule(ctx context.Context, s *Schedule, previous int64) error {
	e, err := t.Append(ctx, "WorkflowScheduleChanged", s.ID, s)
	if err != nil {
		return err
	}
	s.EventID = e
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_schedules VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, s.ID, s.Version, s.Definition, s.Hash, s.State, s.Revision, s.ApprovalAuthority, s.NextDue, s.CreatedAt, e)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE workflow_schedules SET state=$1,revision=$2,approval_authority=$3,next_due=$4,changed_event_id=$5 WHERE tenant_id=$6 AND partner_id=$7 AND actor_id=$8 AND schedule_id=$9 AND version=$10 AND revision=$11`, s.State, s.Revision, s.ApprovalAuthority, s.NextDue, e, t.Scope.Tenant, t.Scope.Partner, t.Actor, s.ID, s.Version, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) Schedules(ctx context.Context, after string, limit int) (*SchedulePage, error) {
	if (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, e := t.Tx.Query(ctx, `SELECT `+scheduleColumns+`,coalesce((SELECT v.version FROM workflow_schedules v WHERE v.schedule_id=s.schedule_id AND v.state='active'),0) FROM workflow_schedules s WHERE actor_id=$1 AND ($2='' OR schedule_id>nullif($2,'')::uuid) AND version=(SELECT max(version) FROM workflow_schedules v WHERE v.schedule_id=s.schedule_id) ORDER BY schedule_id LIMIT $3`, t.Actor, after, limit+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	p := &SchedulePage{Schedules: []ScheduleListing{}}
	for rows.Next() {
		var active int
		s, e := scanSchedule(rows, false, &active)
		if e != nil {
			return nil, e
		}
		if len(p.Schedules) == limit {
			p.Next = p.Schedules[len(p.Schedules)-1].ID
			break
		}
		p.Schedules = append(p.Schedules, ScheduleListing{ScheduleSummary: s.ScheduleSummary, ActiveVersion: active})
	}
	return p, rows.Err()
}
func (t *Transaction) SaveScheduleOccurrence(ctx context.Context, o *ScheduleOccurrence) error {
	e, err := t.Append(ctx, "WorkflowScheduleOccurrence", o.ID, o)
	if err != nil {
		return err
	}
	o.EventID = e
	_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_schedule_occurrences VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, o.ID, o.ScheduleID, o.Version, o.Due, o.Deadline, o.Kind, o.SkippedUntil, o.InputCount, e)
	return err
}
func (t *Transaction) SaveScheduleInput(ctx context.Context, i *ScheduleInput) error {
	e, err := t.Append(ctx, "WorkflowScheduleInput", i.RunID, i)
	if err != nil {
		return err
	}
	i.EventID = e
	_, err = t.Tx.Exec(ctx, `INSERT INTO workflow_schedule_inputs VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, i.ScheduleID, i.Version, i.OccurrenceID, i.FileID, i.RunID, e)
	return err
}
func (t *Transaction) CheckScheduleBinding(ctx context.Context, run string) error {
	var allowed bool
	e := t.Tx.QueryRow(ctx, `SELECT freightctl_scheduled_run_current($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run).Scan(&allowed)
	if e == nil && !allowed {
		return ErrSchedule
	}
	return e
}
func (t *Transaction) ScheduleActiveRuns(ctx context.Context, id string) (int, error) {
	var n int
	e := t.Tx.QueryRow(ctx, `SELECT count(*) FROM workflow_schedule_inputs i JOIN workflow_schedule_occurrences o USING(tenant_id,partner_id,occurrence_id) JOIN workflow_runs r USING(tenant_id,partner_id,run_id) WHERE i.actor_id=$1 AND i.schedule_id=$2 AND o.deadline_at>clock_timestamp() AND EXISTS(SELECT 1 FROM workflow_schedules current_schedule WHERE (current_schedule.tenant_id,current_schedule.partner_id,current_schedule.schedule_id,current_schedule.version)=(i.tenant_id,i.partner_id,i.schedule_id,i.schedule_version) AND current_schedule.state='active') AND r.state NOT IN ('succeeded','cancelled','kept_local')`, t.Actor, id).Scan(&n)
	return n, e
}
func (t *Transaction) ScheduleCandidates(ctx context.Context, id, directory, pattern string, recursive bool, due time.Time, limit int) ([]File, error) {
	if limit < 1 || limit > 64 {
		return nil, ErrLimit
	}
	rows, e := t.Tx.Query(ctx, `SELECT DISTINCT f.file_id::text,f.size_bytes,f.sha256,f.policy,f.accepted_event_id::text FROM files f JOIN events e ON (e.tenant_id,e.partner_id,e.event_id)=(f.tenant_id,f.partner_id,f.accepted_event_id) JOIN namespace_entries n ON (n.tenant_id,n.partner_id,n.file_id)=(f.tenant_id,f.partner_id,f.file_id) WHERE n.kind='file' AND NOT n.deleted AND n.path !~ '(^|/)[.]freightctl-' AND (n.parent_path=$2 OR ($4 AND starts_with(n.path,rtrim($2,'/')||'/'))) AND regexp_replace(n.path,'^.*/','') ~ $3 AND e.happened_at<=$5 AND EXISTS(SELECT 1 FROM events publication WHERE (publication.tenant_id,publication.partner_id,publication.event_id)=(n.tenant_id,n.partner_id,n.changed_event_id) AND publication.happened_at<=$5) AND ($7 OR (((n.owner_actor_id=$8 AND (n.mode & 256)=256) OR (n.owner_actor_id<>$8 AND (n.mode & 32)=32)) AND NOT EXISTS(SELECT 1 FROM namespace_entries a WHERE NOT a.deleted AND a.kind='dir' AND (a.path='/' OR starts_with(n.path,a.path||'/')) AND ((a.owner_actor_id=$8 AND (a.mode & 320)<>320) OR (a.owner_actor_id<>$8 AND (a.mode & 40)<>40))))) AND freightctl_file_available(f.tenant_id,f.partner_id,f.file_id) AND NOT EXISTS(SELECT 1 FROM workflow_schedule_inputs i WHERE i.schedule_id=$1 AND i.file_id=f.file_id) ORDER BY 1 LIMIT $6`, id, directory, pattern, recursive, due, limit, t.Has("admin") && t.Root == "/", t.Actor)
	if e != nil {
		return nil, e
	}
	out := []File{}
	for rows.Next() {
		var f File
		if e = rows.Scan(&f.ID, &f.Size, &f.SHA256, &f.Policy, &f.EventID); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, f)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	allowed := []File{}
	for _, f := range out {
		if e = t.FileAccessible(ctx, f.ID); e == nil {
			allowed = append(allowed, f)
		} else if !errors.Is(e, ErrForbidden) && !errors.Is(e, ErrNotFound) {
			return nil, e
		}
	}
	return allowed, nil
}
func scanOccurrence(row pgx.Row) (*ScheduleOccurrence, error) {
	o := &ScheduleOccurrence{}
	e := row.Scan(&o.ID, &o.ScheduleID, &o.Version, &o.Due, &o.Deadline, &o.Kind, &o.SkippedUntil, &o.InputCount, &o.EventID)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	o.Due = o.Due.UTC()
	o.Deadline = o.Deadline.UTC()
	if o.SkippedUntil != nil {
		v := o.SkippedUntil.UTC()
		o.SkippedUntil = &v
	}
	return o, e
}

const occurrenceColumns = `occurrence_id::text,schedule_id::text,schedule_version,due_at,deadline_at,kind,skipped_until,input_count,event_id::text`

func (t *Transaction) ScheduleHistory(ctx context.Context, id string, after string, limit int) (*ScheduleHistory, error) {
	if !ValidID(id) || (after != "" && !ValidID(after)) || limit < 1 || limit > 100 {
		return nil, ErrLimit
	}
	rows, e := t.Tx.Query(ctx, `SELECT `+occurrenceColumns+` FROM workflow_schedule_occurrences WHERE actor_id=$1 AND schedule_id=$2 AND ($3='' OR occurrence_id>nullif($3,'')::uuid) ORDER BY occurrence_id LIMIT $4`, t.Actor, id, after, limit+1)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	p := &ScheduleHistory{Occurrences: []ScheduleOccurrence{}}
	for rows.Next() {
		o, e := scanOccurrence(rows)
		if e != nil {
			return nil, e
		}
		if len(p.Occurrences) == limit {
			p.Next = p.Occurrences[len(p.Occurrences)-1].ID
			break
		}
		p.Occurrences = append(p.Occurrences, *o)
	}
	return p, rows.Err()
}
func (t *Transaction) ScheduleOccurrence(ctx context.Context, id string) (*ScheduleOccurrenceView, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	o, e := scanOccurrence(t.Tx.QueryRow(ctx, `SELECT `+occurrenceColumns+` FROM workflow_schedule_occurrences WHERE actor_id=$1 AND occurrence_id=$2`, t.Actor, id))
	if e != nil {
		return nil, e
	}
	v := &ScheduleOccurrenceView{ScheduleOccurrence: *o, Inputs: []ScheduleInput{}}
	rows, e := t.Tx.Query(ctx, `SELECT schedule_id::text,schedule_version,occurrence_id::text,file_id::text,run_id::text,event_id::text FROM workflow_schedule_inputs WHERE actor_id=$1 AND occurrence_id=$2 ORDER BY run_id LIMIT 65`, t.Actor, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var i ScheduleInput
		if e = rows.Scan(&i.ScheduleID, &i.Version, &i.OccurrenceID, &i.FileID, &i.RunID, &i.EventID); e != nil {
			return nil, e
		}
		v.Inputs = append(v.Inputs, i)
	}
	if len(v.Inputs) != o.InputCount || len(v.Inputs) > 64 {
		return nil, ErrIsolation
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	rows.Close()
	if o.Kind == "collection" {
		v.Arrival, e = t.ScheduleArrival(ctx, id, false)
		if e != nil {
			return nil, e
		}
	}
	return v, nil
}
func (t *Transaction) SchedulePending(ctx context.Context, id string, version int, limit int) ([]string, error) {
	if !ValidID(id) || version < 1 || limit < 1 || limit > 64 {
		return nil, ErrLimit
	}
	rows, e := t.Tx.Query(ctx, `SELECT i.run_id::text FROM workflow_schedule_inputs i JOIN workflow_runs r USING(tenant_id,partner_id,run_id) JOIN workflow_schedule_occurrences o USING(tenant_id,partner_id,occurrence_id) WHERE i.actor_id=$1 AND i.schedule_id=$2 AND i.schedule_version=$3 AND o.deadline_at>clock_timestamp() AND EXISTS(SELECT 1 FROM workflow_schedules current_schedule WHERE (current_schedule.tenant_id,current_schedule.partner_id,current_schedule.schedule_id,current_schedule.version)=(i.tenant_id,i.partner_id,i.schedule_id,i.schedule_version) AND current_schedule.state='active') AND r.state NOT IN ('succeeded','cancelled','kept_local') ORDER BY o.due_at,i.run_id LIMIT $4`, t.Actor, id, version, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func NewScheduleOccurrence(id string, version int, due time.Time, deadline int, kind string, count int) *ScheduleOccurrence {
	return &ScheduleOccurrence{ID: secure.NewID(), ScheduleID: id, Version: version, Due: due, Deadline: due.Add(time.Duration(deadline) * time.Second), Kind: kind, InputCount: count}
}

// Status observes current metadata without joining an effect guard's lock queue.
// Callers must use CheckScheduleBinding again before any external effect.
func (t *Transaction) ScheduleBindingStatus(ctx context.Context, run string) error {
	var allowed bool
	e := t.Tx.QueryRow(ctx, `SELECT freightctl_scheduled_run_status($1,$2,$3,$4)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, run).Scan(&allowed)
	if e == nil && !allowed {
		return ErrSchedule
	}
	return e
}
