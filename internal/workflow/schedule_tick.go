package workflow

import (
	"context"
	"github.com/ctlplne/freightctl/internal/calendar"
	"github.com/ctlplne/freightctl/internal/store"
	"time"
)

type ScheduleTickRequest struct {
	Limit int `json:"limit"`
}
type ScheduleTickResult struct {
	Kind            string                     `json:"kind"`
	Schedule        store.ScheduleSummary      `json:"schedule"`
	Occurrences     []store.ScheduleOccurrence `json:"occurrences"`
	RunIDs          []string                   `json:"run_ids"`
	Reason          string                     `json:"reason"`
	ExternalContact bool                       `json:"external_contact"`
}

func scheduleMissed(p *calendar.Plan, d *ScheduleDefinition, cursor, timeNow time.Time) (*time.Time, *time.Time) {
	if cursor.After(timeNow) {
		return &cursor, nil
	}
	if d.Missed == "skip" && cursor.Add(time.Duration(d.Grace)*time.Second).Before(timeNow) {
		next := p.Next(timeNow.Add(-time.Duration(d.Grace) * time.Second).Add(-time.Nanosecond))
		until := d.Calendar.End
		if next != nil {
			until = *next
		}
		return next, &until
	}
	if d.Missed == "latest" {
		last := p.Previous(timeNow.Add(time.Nanosecond))
		if last != nil && last.After(cursor) {
			return last, last
		}
	}
	return &cursor, nil
}
func (s *Service) TickSchedule(ctx context.Context, scope store.Scope, id string, version int, key string, x ScheduleTickRequest) (*Result, error) {
	if !store.ValidID(id) || version < 1 || !keyPattern.MatchString(key) || x.Limit < 1 || x.Limit > 100 {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, e := s.scheduleBegin(ctx, scope, "workflow_execute", "list", "read")
	if e != nil {
		return nil, e
	}
	defer t.Tx.Rollback(ctx)
	_, meaning, e := digest(struct {
		Kind, ID string
		Version  int
		Input    ScheduleTickRequest
	}{"schedule_tick", id, version, x})
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
	if record.State != "active" || record.ApprovalAuthority != t.AuthorityRevision || d.Authority != t.AuthorityRevision {
		return nil, store.ErrSchedule
	}
	if x.Limit > d.CatchUp {
		return nil, store.ErrLimit
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
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return nil, e
	}
	out := ScheduleTickResult{Kind: "workflow_schedule_tick", Schedule: record.ScheduleSummary, Occurrences: []store.ScheduleOccurrence{}, RunIDs: []string{}, Reason: "not_due"}
	previous := record.Revision
	changed := false
	for count := 0; count < x.Limit && record.NextDue != nil && !record.NextDue.After(now); count++ {
		due := *record.NextDue
		chosen, skipped := scheduleMissed(p, d, due, now)
		if skipped != nil {
			o := store.NewScheduleOccurrence(id, version, due, d.Deadline, "skipped", 0)
			o.SkippedUntil = skipped
			if e = t.SaveScheduleOccurrence(ctx, o); e != nil {
				return nil, e
			}
			out.Occurrences = append(out.Occurrences, *o)
			record.NextDue = chosen
			changed = true
			out.Reason = "skipped_missed_window"
			continue
		}
		kind := "empty"
		deadline := due.Add(time.Duration(d.Deadline) * time.Second)
		if !deadline.After(now) {
			kind = "missed"
		} else if d.Collection != nil {
			arrivalEnd := due.Add(time.Duration(d.Collection.Arrival.Deadline) * time.Second)
			if arrivalEnd.After(now) {
				active, e := t.ScheduleCollectionActive(ctx, id)
				if e != nil {
					return nil, e
				}
				if active >= d.MaxActive {
					out.Reason = "collection_concurrency"
					break
				}
			}
			occurrence := store.NewScheduleOccurrence(id, version, due, d.Deadline, "collection", 0)
			if e = t.SaveScheduleOccurrence(ctx, occurrence); e != nil {
				return nil, e
			}
			if e = s.stageScheduleArrival(ctx, t, record, d, occurrence, now); e != nil {
				return nil, e
			}
			out.Occurrences = append(out.Occurrences, *occurrence)
			record.NextDue = p.Next(due)
			changed = true
			out.Reason = "awaiting_source_arrival"
			continue
		} else {
			active, e := t.ScheduleActiveRuns(ctx, id)
			if e != nil {
				return nil, e
			}
			capacity := d.MaxActive - active
			if capacity <= 0 {
				out.Reason = "schedule_concurrency"
				break
			}
			if capacity > d.MaxFiles {
				capacity = d.MaxFiles
			}
			if e = t.DeliveryAdmission(ctx, 1); e != nil {
				if e == store.ErrLimit {
					out.Reason = "delivery_capacity"
					break
				}
				return nil, e
			}
			var used int
			if e = t.Tx.QueryRow(ctx, `SELECT count(*) FROM delivery_intents WHERE actor_id=$1 AND state NOT IN ('succeeded','blocked','cancelled')`, t.Actor).Scan(&used); e != nil {
				return nil, e
			}
			free := (128 - used) / len(workflow.Steps)
			if free < capacity {
				capacity = free
			}
			if capacity <= 0 {
				out.Reason = "delivery_capacity"
				break
			}
			candidates, e := t.ScheduleCandidates(ctx, id, d.Source.Directory, d.Source.Regex, d.Source.Recursive, due, capacity)
			if e != nil {
				return nil, e
			}
			if len(candidates) > 0 {
				for _, source := range candidates {
					if source.Size > s.Custody.MaxFile {
						return nil, store.ErrLimit
					}
				}
				o := store.NewScheduleOccurrence(id, version, due, d.Deadline, "queued", len(candidates))
				if e = t.SaveScheduleOccurrence(ctx, o); e != nil {
					return nil, e
				}
				for i := range candidates {
					source := &candidates[i]
					run, e := s.stageRun(ctx, t, RunRequest{Workflow: d.Workflow, FileID: source.ID}, workflow, source, d.StorageID)
					if e != nil {
						return nil, e
					}
					input := &store.ScheduleInput{ScheduleID: id, Version: version, OccurrenceID: o.ID, FileID: source.ID, RunID: run.ID}
					if e = t.SaveScheduleInput(ctx, input); e != nil {
						return nil, e
					}
					out.RunIDs = append(out.RunIDs, run.ID)
				}
				out.Occurrences = append(out.Occurrences, *o)
				record.NextDue = p.Next(due)
				changed = true
				out.Reason = "queued"
				continue
			}
		}
		o := store.NewScheduleOccurrence(id, version, due, d.Deadline, kind, 0)
		if e = t.SaveScheduleOccurrence(ctx, o); e != nil {
			return nil, e
		}
		out.Occurrences = append(out.Occurrences, *o)
		record.NextDue = p.Next(due)
		changed = true
		out.Reason = kind
	}
	if changed {
		record.Revision++
		if e = t.SaveSchedule(ctx, record, previous); e != nil {
			return nil, e
		}
	}
	if record.NextDue == nil && len(out.Occurrences) == 0 {
		out.Reason = "calendar_exhausted"
	}
	out.Schedule = record.ScheduleSummary
	return scheduleResult(t, ctx, key, meaning, id, out)
}

// ScheduleReady is a read-only polling check. A waiting worker does not append
// one command receipt every second while capacity or independent review blocks.
func (s *Service) ScheduleReady(ctx context.Context, scope store.Scope, id string, version int) (bool, error) {
	t, e := s.scheduleRead(ctx, scope)
	if e != nil {
		return false, e
	}
	defer t.Tx.Rollback(ctx)
	record, e := t.Schedule(ctx, id, version, false)
	if e != nil {
		return false, e
	}
	d, _, e := scheduleDefinition(record)
	if e != nil {
		return false, e
	}
	if record.State != "active" || record.ApprovalAuthority != t.AuthorityRevision || d.Authority != t.AuthorityRevision {
		return false, store.ErrSchedule
	}
	now, e := t.DatabaseTime(ctx)
	if e != nil {
		return false, e
	}
	ready := record.NextDue != nil && !record.NextDue.After(now)
	if ready && record.NextDue.Add(time.Duration(d.Deadline)*time.Second).After(now) && !(d.Missed == "skip" && record.NextDue.Add(time.Duration(d.Grace)*time.Second).Before(now)) {
		active, e := t.ScheduleActiveRuns(ctx, id)
		if d.Collection != nil {
			active, e = t.ScheduleCollectionActive(ctx, id)
		}
		if e != nil {
			return false, e
		}
		var used int
		if e = t.Tx.QueryRow(ctx, `SELECT count(*) FROM delivery_intents WHERE actor_id=$1 AND state NOT IN ('succeeded','blocked','cancelled')`, t.Actor).Scan(&used); e != nil {
			return false, e
		}
		_, workflow, e := approved(ctx, t, d.Workflow)
		if e != nil {
			return false, e
		}
		ready = active < d.MaxActive && (d.Collection != nil || 128-used >= len(workflow.Steps))
		if d.Collection != nil && !record.NextDue.Add(time.Duration(d.Collection.Arrival.Deadline)*time.Second).After(now) {
			ready = true
		}
	}
	if e = t.Reauthorize(ctx); e != nil {
		return false, e
	}
	return ready, t.Tx.Commit(ctx)
}
