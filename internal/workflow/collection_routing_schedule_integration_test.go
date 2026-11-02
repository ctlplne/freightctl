//go:build integration

package workflow

import (
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// Supply a trusted source-adapter result while keeping the real PostgreSQL,
// storage, occurrence, arrival and ordinary collection transactions intact.
// This is not a stock SFTP or calendar-browser qualification claim.
func scheduledCapturedRoutingFixture(t *testing.T) (*fixture, *CollectionView, CollectionRoutingSelection, store.ScheduleSummary, string) {
	t.Helper()
	f, calendar, _ := scheduledCollectionFixture(t)
	w, err := f.s.Configuration(f.ctx, f.scope, calendar.Workflow.ID, calendar.Workflow.Version)
	if err != nil {
		t.Fatal(err)
	}
	var definition Definition
	if Decode(w.Definition, &definition) != nil {
		t.Fatal("scheduled workflow definition")
	}
	definition.Schema = 2
	definition.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "local_review_required"}}}
	original := f.approved(t, definition)
	calendar.Workflow = Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	calendar.Calendar.Start, calendar.Calendar.End = due, due.Add(time.Minute)
	calendar.Calendar.Times = []string{due.Format("15:04:05")}
	schedule := saveSchedule(t, f, calendar, "", 0, "captured-routing-calendar")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "captured-routing-original-due")
	if len(tick.Occurrences) != 1 {
		t.Fatal("expected one original occurrence")
	}
	id := tick.Occurrences[0].ID
	arrival, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	owner := secure.NewID()
	claimed, _, _, err := f.s.claimArrivalProbe(f.ctx, f.scope, id, arrival.Arrival.Hash, owner)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}}}
	_, hash, _ := digest(manifest)
	if _, err = f.s.finishArrivalProbe(f.scope, id, owner, claimed.Fence, "captured-routing-ready", secure.Digest([]byte("captured-routing-ready")), "ready", "verified_ready_manifest_observed", manifest, hash); err != nil {
		t.Fatal(err)
	}
	arrival, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AdmitScheduleArrival(f.ctx, f.scope, id, "captured-routing-admit-source", Decision{Hash: arrival.Arrival.Hash, Revision: arrival.Arrival.Revision}); err != nil {
		t.Fatal(err)
	}
	arrival, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || arrival.Collection == nil {
		t.Fatal("scheduled source was not admitted", err)
	}
	job := arrival.Collection.Job
	collector := secure.NewID()
	job, _, _, err = f.s.claimCollection(f.ctx, f.scope, job.ID, job.Hash, collector)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.captureCollectionManifest(f.ctx, f.scope, job.ID, collector, job.Fence, manifest, hash); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || len(view.Inputs) != 1 {
		t.Fatal("captured input inventory", err)
	}
	input := view.Inputs[0]
	if _, _, err = f.s.Custody.Disk.StageGenerated(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, input.ObjectID), 3, func(w io.Writer) error { _, e := io.WriteString(w, "abc"); return e }); err != nil {
		t.Fatal(err)
	}
	captured := finishSealedCollection(t, f, view.Job, collector, view.Inputs)
	definition.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: definition.Steps[0].ID}}}
	target := revisedCollectionRoutingWorkflow(t, f, original, definition)
	return f, captured, CollectionRoutingSelection{Collection: Decision{Hash: captured.Job.Hash, Revision: captured.Job.Revision}, Workflow: Reference{ID: target.ID, Version: target.Version, Hash: target.Hash}, Authority: 1}, schedule, id
}

func TestCapturedRoutingRetainsOriginalCalendarCutoffsAndSuspensionFencesEveryPhase(t *testing.T) {
	for _, phase := range []string{"proposed", "approved", "queued"} {
		t.Run(phase, func(t *testing.T) {
			f, captured, x, schedule, occurrence := scheduledCapturedRoutingFixture(t)
			original, err := collectionDefinition(captured.Job)
			if err != nil || original.Schedule == nil || original.Schedule.OccurrenceID != occurrence || original.Schedule.Schedule.ID != schedule.ID || !captured.Job.Deadline.Equal(original.Schedule.Deadline) || original.Schedule.Deadline.Sub(original.Schedule.Due) != time.Duration(original.Timeout)*time.Second {
				t.Fatal("capture lost the original occurrence or deadline", err)
			}
			arrival, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, occurrence)
			if err != nil {
				t.Fatal(err)
			}
			a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "calendar-routing-propose")
			if phase != "proposed" {
				a = decideRoutingAuthorization(t, f, a, "approve", "calendar-routing-approve")
			}
			if phase == "queued" {
				if _, err = f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "calendar-routing-queue", x.Collection); err != nil {
					t.Fatal(err)
				}
			}
			view, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
			if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
				t.Fatal("corrected rules rewrote the calendar capture", err)
			}
			// The corrected revision can change the plan, but it cannot create
			// a fresh occurrence, move either cutoff or refresh source attempts.
			after, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, occurrence)
			if err != nil || !reflect.DeepEqual(after.Arrival, arrival.Arrival) {
				t.Fatal("corrected routing changed the original arrival", err)
			}
			if _, err = f.s.ControlSchedule(f.ctx, f.scope, schedule.ID, schedule.Version, "suspend", "suspend-corrected-routing-calendar", Decision{Hash: schedule.Hash, Revision: schedule.Revision}); err != nil {
				t.Fatal(err)
			}
			before := routingPreviewCounts(t, f)
			if phase == "proposed" {
				if _, err = f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, "suspended-calendar-cannot-approve", "approve", Decision{Hash: a.Hash, Revision: a.Revision}); !errors.Is(err, store.ErrCollection) {
					t.Fatal("suspended calendar allowed a new routing approval", err)
				}
			}
			if _, err = f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "suspended-calendar-cannot-route", x.Collection); !errors.Is(err, store.ErrCollection) {
				t.Fatal("corrected rules bypassed the original suspended calendar", err)
			}
			if phase == "queued" {
				if len(view.Inputs) != 1 || view.Inputs[0].RunID == nil {
					t.Fatal("corrected scheduled input was not queued")
				}
				status, err := f.s.Status(f.ctx, f.scope, *view.Inputs[0].RunID)
				if err != nil || status.Run.RoutingID != a.ID || status.Run.WorkflowVersion != x.Workflow.Version || status.Run.WorkflowHash != x.Workflow.Hash || len(status.Steps) != 1 {
					t.Fatal("scheduled run lost corrected routing lineage", err)
				}
				id := status.Steps[0].DeliveryID
				if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, id, secure.NewID()); !errors.Is(err, store.ErrCollection) {
					t.Fatal("calendar suspension allowed a queued effect to start", err)
				}
				var attempts int
				if err = f.admin.QueryRow(f.ctx, `SELECT attempts FROM delivery_intents WHERE delivery_id=$1`, id).Scan(&attempts); err != nil || attempts != 0 {
					t.Fatal("calendar refusal consumed a transfer attempt", attempts, err)
				}
			}
			if routingPreviewCounts(t, f) != before {
				t.Fatal("suspended calendar left partial approvals or execution effects")
			}
			if phase == "proposed" {
				a = decideRoutingAuthorization(t, f, a, "withdraw", "withdraw-suspended-calendar-proposal")
				if a.State != "withdrawn" {
					t.Fatal("calendar suspension stranded a nonexecuting proposal")
				}
			}
			var count int
			if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM workflow_schedule_occurrences WHERE schedule_id=$1`, schedule.ID).Scan(&count); err != nil || count != 1 {
				t.Fatal("routing invented a replacement calendar occurrence", count, err)
			}
		})
	}
}
