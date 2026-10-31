package workflow

import (
	"context"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type ScheduleArrivalView struct {
	Arrival    *store.ScheduleArrival `json:"arrival"`
	Schedule   *store.Schedule        `json:"schedule"`
	Current    bool                   `json:"current_authority"`
	Observed   string                 `json:"observed_state"`
	Timeliness string                 `json:"arrival_timeliness"`
	CanProbe   bool                   `json:"probe_due"`
	Collection *CollectionView        `json:"collection,omitempty"`
}

func (s *Service) ScheduleArrivalStatus(ctx context.Context, scope store.Scope, id string) (*ScheduleArrivalView, error) {
	if !store.ValidID(id) {
		return nil, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	t, err := s.scheduleRead(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	for count := 0; count < 3; count++ {
		a, err := t.ScheduleArrival(ctx, id, false)
		if err != nil {
			return nil, err
		}
		binding, err := arrivalBinding(a)
		if err != nil {
			return nil, err
		}
		record, err := t.Schedule(ctx, a.ScheduleID, a.Version, false)
		if err != nil {
			return nil, err
		}
		d, _, err := scheduleDefinition(record)
		if err != nil || d.Collection == nil {
			if err == nil {
				err = store.ErrState
			}
			return nil, err
		}
		now, err := t.DatabaseTime(ctx)
		if err != nil {
			return nil, err
		}
		var current bool
		if err = t.Tx.QueryRow(ctx, `SELECT freightctl_arrival_current($1,$2,$3,$4)`, scope.Tenant, scope.Partner, t.Actor, a.Definition).Scan(&current); err != nil {
			return nil, err
		}
		v := &ScheduleArrivalView{Arrival: a, Schedule: record, Current: current && binding.Deadline.After(now) && a.State != "cancelled" && a.State != "missing" && a.State != "expired", Observed: a.State, Timeliness: "not_observed"}
		if a.Observed != nil {
			v.Timeliness = "on_time"
			if a.Observed.After(binding.LateAfter) {
				v.Timeliness = "late"
			}
		}
		switch a.State {
		case "waiting", "probing", "attention":
			if !binding.ArrivalDeadline.After(now) {
				v.Observed = "arrival_window_elapsed"
				v.CanProbe = true
			} else {
				if a.State == "waiting" && now.After(binding.LateAfter) {
					v.Observed = "late_waiting"
				}
				v.CanProbe = v.Current && !a.Next.After(now) && (a.State != "probing" || a.Until == nil || !a.Until.After(now))
				limit := (d.Collection.Arrival.Deadline+d.Collection.Arrival.Poll-1)/d.Collection.Arrival.Poll + 1
				if a.Probes >= limit {
					v.CanProbe = false
					v.Observed = "probe_budget_exhausted"
				}
			}
		case "ready":
			if !binding.Deadline.After(now) {
				v.Observed = "execution_window_elapsed"
			}
		}
		if a.JobID != nil {
			j, err := t.Collection(ctx, *a.JobID, false)
			if err != nil {
				return nil, err
			}
			v.Collection, err = collectionView(ctx, t, j)
			if err != nil {
				return nil, err
			}
		}
		after, err := t.ScheduleArrival(ctx, id, false)
		if err != nil {
			return nil, err
		}
		if after.Revision == a.Revision {
			return v, t.Tx.Commit(ctx)
		}
	}
	return nil, store.ErrRevision
}
