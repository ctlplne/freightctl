package main

import (
	"context"
	"encoding/json"
	"errors"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type scheduleCLIOptions struct {
	testCLIOptions
	Version  int
	Execute  bool
	Poll     time.Duration
	MaxPolls int
}

func runSchedule(ctx context.Context, command string, o scheduleCLIOptions) error {
	if o.MaxFile < 1 || o.MaxFile > 1<<30 || o.MaxStored < o.MaxFile {
		return errors.New("invalid workflow storage budget")
	}
	secret, e := secure.ReadSecret(o.Token, 64)
	if e != nil {
		return e
	}
	scope := store.Scope{Tenant: o.Tenant, Partner: o.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	db, e := store.Open(ctx, o.DSN)
	if e != nil {
		return e
	}
	defer db.Pool.Close()
	c := &custody.Service{DB: db, MaxFile: o.MaxFile, MaxStored: o.MaxStored}
	if command == "workflow-schedule-preview" || command == "workflow-schedule-draft" || command == "workflow-schedule-activate" || command == "workflow-schedule-tick" || command == "workflow-schedule-worker" {
		disk, e := custody.OpenExisting(o.Storage)
		if e != nil {
			return e
		}
		defer disk.Close()
		c.Disk = disk
	}
	service := &workflow.Service{Custody: c}
	decode := func(target any) error {
		f, e := os.Open(o.Input)
		if e != nil {
			return errors.New("cannot open protected schedule request reference")
		}
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !st.Mode().IsRegular() || st.Size() > 32<<10 {
			return workflow.ErrInput
		}
		b, e := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if e != nil {
			return e
		}
		return workflow.Decode(b, target)
	}
	var out any
	switch command {
	case "workflow-schedule-preview":
		var x workflow.ScheduleSelection
		if e = decode(&x); e == nil {
			out, e = service.PreviewSchedule(ctx, scope, x)
		}
	case "workflow-schedule-draft":
		var x workflow.ScheduleDraftRequest
		if e = decode(&x); e == nil {
			out, e = service.DraftSchedule(ctx, scope, o.Key, x)
		}
	case "workflow-schedule-status":
		out, e = service.ScheduleStatus(ctx, scope, o.ID, o.Version)
	case "workflow-schedule-workflows":
		out, e = service.SchedulableWorkflows(ctx, scope, o.After, o.Limit)
	case "workflow-schedule-list":
		out, e = service.Schedules(ctx, scope, o.After, o.Limit)
	case "workflow-schedule-history":
		out, e = service.ScheduleHistory(ctx, scope, o.ID, o.After, o.Limit)
	case "workflow-schedule-occurrence":
		out, e = service.ScheduleOccurrence(ctx, scope, o.Run)
	case "workflow-schedule-tick":
		var x workflow.ScheduleTickRequest
		if e = decode(&x); e == nil {
			out, e = service.TickSchedule(ctx, scope, o.ID, o.Version, o.Key, x)
		}
	case "workflow-schedule-activate", "workflow-schedule-suspend", "workflow-schedule-revoke":
		var x workflow.Decision
		if e = decode(&x); e == nil {
			out, e = service.ControlSchedule(ctx, scope, o.ID, o.Version, command[len("workflow-schedule-"):], o.Key, x)
		}
	case "workflow-schedule-worker":
		if !store.ValidID(o.ID) || o.Version < 1 || o.Poll < time.Second || o.Poll > time.Minute || o.MaxPolls < 0 || o.MaxPolls > 1000000 {
			return workflow.ErrInput
		}
		stop, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return scheduleWorker(stop, service, scope, o)
	default:
		return workflow.ErrInput
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
func scheduleWorker(ctx context.Context, service *workflow.Service, scope store.Scope, o scheduleCLIOptions) error {
	enc := json.NewEncoder(os.Stdout)
	lastWait := ""
	reportWait := func(reason string) error {
		if lastWait == reason {
			return nil
		}
		lastWait = reason
		return enc.Encode(map[string]string{"state": "waiting", "reason": reason})
	}
	for poll := 0; o.MaxPolls == 0 || poll < o.MaxPolls; poll++ {
		if ctx.Err() != nil {
			return nil
		}
		status, e := service.ScheduleStatus(ctx, scope, o.ID, o.Version)
		if e != nil {
			return e
		}
		if !status.CurrentAuthority {
			return store.ErrSchedule
		}
		if o.Execute {
			for _, run := range status.Pending {
				runStatus, readErr := service.Status(ctx, scope, run)
				if readErr != nil {
					return readErr
				}
				if runStatus.ObservedState == "succeeded" {
					if _, e = service.RefreshRun(ctx, scope, run, "schedule-project:"+run); e != nil {
						return e
					}
					continue
				}
				stepID := ""
				for _, step := range runStatus.Steps {
					if step.State != "succeeded" {
						stepID = step.ID
						break
					}
				}
				if stepID == "" {
					return store.ErrState
				}
				_, e = service.Work(ctx, scope, run, "schedule-worker:"+run+":"+stepID)
				if e != nil {
					if ctx.Err() != nil {
						return nil
					}
					if !workflow.ScheduleWait(e) {
						return e
					}
					reason := "workflow_policy_or_capacity"
					if errors.Is(e, store.ErrDispatchApproval) {
						reason = "independent_dispatch_approval_required"
					}
					if e = reportWait(reason); e != nil {
						return e
					}
					continue
				}
				lastWait = ""
				if e = enc.Encode(map[string]string{"state": "worked", "run_id": run}); e != nil {
					return e
				}
			}
		}
		ready, e := service.ScheduleReady(ctx, scope, o.ID, o.Version)
		if e != nil {
			return e
		}
		if ready {
			key := "schedule-tick:" + secure.NewID()
			r, e := service.TickSchedule(ctx, scope, o.ID, o.Version, key, workflow.ScheduleTickRequest{Limit: 1})
			if e != nil {
				if !workflow.ScheduleWait(e) {
					return e
				}
				if e = reportWait("schedule_policy_or_capacity"); e != nil {
					return e
				}
			} else {
				lastWait = ""
				if e = enc.Encode(r); e != nil {
					return e
				}
			}
		}
		if o.MaxPolls > 0 && poll+1 >= o.MaxPolls {
			break
		}
		timer := time.NewTimer(o.Poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}
