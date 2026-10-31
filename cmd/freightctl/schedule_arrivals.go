package main

import (
	"context"
	"encoding/json"
	"strconv"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// Only the explicitly executing schedule worker calls this coordinator. Each
// stage uses the ordinary service and its own durable receipt, never a direct
// network shortcut. A later poll resumes from PostgreSQL after process death.
func workScheduledArrival(ctx context.Context, service *workflow.Service, scope store.Scope, id string, enc *json.Encoder) (string, error) {
	v, err := service.ScheduleArrivalStatus(ctx, scope, id)
	if err != nil {
		return "", err
	}
	a := v.Arrival
	switch a.State {
	case "waiting", "probing", "attention":
		// An attention state needs a human retry. The cutoff can still be
		// recorded without contacting a source or granting new authority.
		if !v.CanProbe || (a.State == "attention" && v.Observed != "arrival_window_elapsed") {
			return v.Observed, nil
		}
		next := a.Probes + 1
		if a.State == "probing" {
			next = a.Probes
		}
		r, err := service.ProbeScheduleArrival(ctx, scope, id, "arrival-probe:"+id+":"+strconv.Itoa(next), workflow.CollectionWorkRequest{Hash: a.Hash})
		if err != nil {
			return "", err
		}
		return "", enc.Encode(r)
	case "ready":
		if !v.Current && v.Observed != "execution_window_elapsed" {
			return "arrival_authority_required", nil
		}
		r, err := service.AdmitScheduleArrival(ctx, scope, id, "arrival-admit:"+id+":"+strconv.FormatInt(a.Revision, 10), workflow.Decision{Hash: a.Hash, Revision: a.Revision})
		if err != nil {
			return "", err
		}
		return "", enc.Encode(r)
	case "admitted":
		if v.Collection == nil {
			return "", store.ErrState
		}
	default:
		return "", nil
	}
	j := v.Collection.Job
	ready, err := service.CollectionReady(ctx, scope, j.ID)
	if err != nil {
		return "", err
	}
	if ready.WorkDue {
		next := j.Attempts + 1
		if j.State == "reading" {
			next = j.Attempts
		}
		r, err := service.WorkCollection(ctx, scope, j.ID, "arrival-collect:"+j.ID+":"+strconv.Itoa(next), workflow.CollectionWorkRequest{Hash: j.Hash})
		if err != nil {
			return "", err
		}
		return "", enc.Encode(r)
	}
	if ready.RouteReady {
		// Readiness can race an intake/capacity change. A fresh operation key
		// prevents a harmless raced no-op receipt from freezing all retries.
		r, err := service.RefreshCollection(ctx, scope, j.ID, "arrival-route:"+secure.NewID(), workflow.Decision{Hash: j.Hash, Revision: j.Revision})
		if err != nil {
			return "", err
		}
		return "", enc.Encode(r)
	}
	worked := false
	for _, input := range v.Collection.Inputs {
		if input.JobID != j.ID || input.RunID == nil {
			continue
		}
		run, err := service.Status(ctx, scope, *input.RunID)
		if err != nil {
			return "", err
		}
		if run.ObservedState == "succeeded" || run.ObservedState == "kept_local" {
			if _, err = service.RefreshRun(ctx, scope, *input.RunID, "schedule-project:"+*input.RunID); err != nil {
				return "", err
			}
			continue
		}
		stepID := ""
		for _, step := range run.Steps {
			if step.State != "succeeded" {
				stepID = step.ID
				break
			}
		}
		if stepID == "" {
			return "", store.ErrState
		}
		r, err := service.Work(ctx, scope, *input.RunID, "schedule-worker:"+*input.RunID+":"+stepID)
		if err != nil {
			return "", err
		}
		if err = enc.Encode(r); err != nil {
			return "", err
		}
		worked = true
	}
	if worked {
		return "", nil
	}
	return ready.Reason, nil
}
