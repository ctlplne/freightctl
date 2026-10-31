//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/ctlplne/freightctl/internal/calendar"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestArrivalObservationReceiptConflictRollsBackFrozenReadyAndAdmission(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	schedule := saveSchedule(t, f, x, "", 0, "atomic-ready")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "existing-tick-key")
	id := tick.Occurrences[0].ID
	v, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	owner := secure.NewID()
	claimed, _, _, err := f.s.claimArrivalProbe(f.ctx, f.scope, id, v.Arrival.Hash, owner)
	if err != nil {
		t.Fatal(err)
	}
	m := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}}}
	_, hash, _ := digest(m)
	meaning := secure.Digest([]byte("one-arrival-probe"))
	if _, err = f.s.finishArrivalProbe(f.scope, id, owner, claimed.Fence, "existing-tick-key", meaning, "ready", "verified_ready_manifest_observed", m, hash); err == nil {
		t.Fatal("conflicting command key recorded an unrelated ready observation")
	}
	v, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || v.Arrival.State != "probing" || v.Arrival.Revision != claimed.Revision || v.Arrival.Manifest != nil || v.Arrival.JobID != nil || !v.Arrival.Until.Equal(*claimed.Until) {
		t.Fatal("receipt failure left a partial ready projection", v, err)
	}
	if _, err = f.s.finishArrivalProbe(f.scope, id, owner, claimed.Fence, "atomic-ready-observed", meaning, "ready", "verified_ready_manifest_observed", m, hash); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.arrivalBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tx.ScheduleArrival(f.ctx, id, true)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	if _, err = f.s.admitScheduleArrival(f.ctx, tx, a); err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	tx.Tx.Rollback(f.ctx)
	after, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || after.Arrival.State != "ready" || after.Arrival.JobID != nil || after.Arrival.Revision != v.Arrival.Revision {
		t.Fatal("rolled back admission left an arrival or job link", after, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, "SELECT count(*) FROM workflow_collection_jobs").Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
}

func TestArrivalCutoffRecordsMissingWithoutSourceWorkAndKeepsOriginalReceipt(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	x.Arrival = &ScheduleArrivalSelection{LateAfter: 0, Deadline: 1, Poll: 1}
	schedule := saveSchedule(t, f, x, "", 0, "missing-cutoff")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "missing-due")
	id := tick.Occurrences[0].ID
	before, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	waitSchedule(t, f, due.Add(time.Second))
	observed, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || !observed.CanProbe || observed.Observed != "arrival_window_elapsed" || observed.Arrival.State != "waiting" {
		t.Fatal("read-only status changed durable arrival or lost cutoff action", observed, err)
	}
	xwork := CollectionWorkRequest{Hash: before.Arrival.Hash}
	first, err := f.s.ProbeScheduleArrival(f.ctx, f.scope, id, "missing-original", xwork)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.ProbeScheduleArrival(f.ctx, f.scope, id, "missing-original", xwork)
	if err != nil || !again.Replayed || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal("missing original receipt changed", err)
	}
	after, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || after.Arrival.State != "missing" || after.Arrival.Probes != 0 || after.Arrival.Manifest != nil || after.Arrival.JobID != nil || after.Current || after.CanProbe || after.Timeliness != "not_observed" {
		t.Fatal("cutoff invented source observation or consumed a byte/probe attempt", after, err)
	}
	if _, err = f.s.AdmitScheduleArrival(f.ctx, f.scope, id, "missing-cannot-admit", Decision{Hash: after.Arrival.Hash, Revision: after.Arrival.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("missing arrival admitted a collection", err)
	}
}

func TestSourceOnlyCalendarAdmitsCollectionWithoutAdminOrDeliver(t *testing.T) {
	f := setup(t)
	parent := f.scope
	child, account := approvalPeer(t, f, "Scheduled local collector", append([]string{}, store.DefaultPermissions...))
	result, err := f.s.RegisterConnection(f.ctx, child, "calendar-source-connection", f.request)
	if err != nil {
		t.Fatal(err)
	}
	var connection ConnectionView
	if json.Unmarshal(result.Resource, &connection) != nil {
		t.Fatal("connection")
	}
	permissions := []string{}
	for _, p := range store.DefaultPermissions {
		if p != "admin" && p != "deliver" {
			permissions = append(permissions, p)
		}
	}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, parent, "calendar-no-admin-or-deliver", store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Scheduled local collector", Root: "/", Permissions: permissions}}); err != nil {
		t.Fatal(err)
	}
	f.scope = child
	f.connection = connection
	source := collectionTestSource()
	source.Contract = ScheduledCollectionContract
	source.Manifest = "settlement-{due_utc}.ready.json"
	source.Directory = "/"
	source.Connection = Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}
	definition := f.definition()
	definition.Source = &source
	definition.Steps = []Step{}
	w := f.approved(t, definition)
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	x := ScheduleSelection{Name: "Local scheduled collector", Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Source: ScheduleSourceSelection{Directory: "/", Pattern: source.Manifest, Kind: "sftp.collect"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Second), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 1, MaxActive: 1, MaxFiles: source.MaxFiles, Deadline: 60, Grace: 1, ExpectedAuthority: 2, Arrival: &ScheduleArrivalSelection{LateAfter: 0, Deadline: 10, Poll: 1}}
	preview, err := f.s.PreviewSchedule(f.ctx, child, x)
	if err != nil || len(preview.Effects) != 0 || preview.Definition.Collection == nil {
		t.Fatal("local calendar required a dummy receiver", preview, err)
	}
	draft, err := f.s.DraftSchedule(f.ctx, child, "local-calendar-draft", ScheduleDraftRequest{Selection: x, Hash: preview.Hash})
	if err != nil {
		t.Fatal(err)
	}
	var saved ScheduleResource
	if json.Unmarshal(draft.Resource, &saved) != nil {
		t.Fatal("draft")
	}
	if _, err = f.s.ControlSchedule(f.ctx, child, saved.Schedule.ID, 1, "activate", "local-calendar-activate", Decision{Hash: saved.Schedule.Hash, Revision: saved.Schedule.Revision}); err != nil {
		t.Fatal(err)
	}
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, saved.Schedule, "local-calendar-due")
	id := tick.Occurrences[0].ID
	v, err := f.s.ScheduleArrivalStatus(f.ctx, child, id)
	if err != nil || !v.Current {
		t.Fatal(v, err)
	}
	owner := secure.NewID()
	a, _, _, err := f.s.claimArrivalProbe(f.ctx, child, id, v.Arrival.Hash, owner)
	if err != nil {
		t.Fatal(err)
	}
	m := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}}}
	_, hash, _ := digest(m)
	if _, err = f.s.finishArrivalProbe(child, id, owner, a.Fence, "local-calendar-ready", secure.Digest([]byte("local-calendar-ready")), "ready", "verified_ready_manifest_observed", m, hash); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.ScheduleArrivalStatus(f.ctx, child, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.AdmitScheduleArrival(f.ctx, child, id, "local-calendar-admit", Decision{Hash: v.Arrival.Hash, Revision: v.Arrival.Revision}); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.ScheduleArrivalStatus(f.ctx, child, id)
	if err != nil || v.Collection == nil || len(v.Collection.Job.Definition) == 0 {
		t.Fatal(v, err)
	}
	d, err := collectionDefinition(v.Collection.Job)
	if err != nil || len(d.Effects) != 0 {
		t.Fatal("local calendar acquired a downstream effect", d, err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM workflow_runs)+(SELECT count(*) FROM delivery_intents)").Scan(&count); err != nil || count != 0 {
		t.Fatal("source-only admission queued sending", count, err)
	}
	// The same identity cannot add forwarding by merely selecting a workflow
	// with effects. Its absent deliver grant remains an ordinary hard boundary.
	definition.Steps = f.definition().Steps[:1]
	forward := f.approved(t, definition)
	x.Workflow = Reference{ID: forward.ID, Version: forward.Version, Hash: forward.Hash}
	if _, err = f.s.PreviewSchedule(f.ctx, child, x); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("calendar forwarding acquired an absent deliver grant", err)
	}
}

func TestArrivalSQLCannotBackdateVerifiedObservationBeforeLateBoundary(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	x.Arrival.LateAfter = 0
	schedule := saveSchedule(t, f, x, "", 0, "database-observation-time")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "database-observation-due")
	id := tick.Occurrences[0].ID
	v, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	waitSchedule(t, f, due.Add(time.Second))
	a, _, _, err := f.s.claimArrivalProbe(f.ctx, f.scope, id, v.Arrival.Hash, secure.NewID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.arrivalBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	claimedAfter, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}}}
	encoded, hash, _ := digest(m)
	old := a.Revision
	a.Revision++
	a.State = "ready"
	a.Owner = ""
	a.Until = nil
	a.Manifest = encoded
	a.ManifestHash = &hash
	a.Observed = &due
	a.Reason = "verified_ready_manifest_observed"
	if err = tx.SaveScheduleArrival(f.ctx, a, old); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	after, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || after.Timeliness != "late" || after.Arrival.Observed == nil || after.Arrival.Observed.Before(claimedAfter) {
		t.Fatal("caller backdated a verified late manifest into an on-time observation", after, err)
	}
	var journal time.Time
	if err = f.admin.QueryRow(f.ctx, `SELECT happened_at FROM events WHERE event_id=(SELECT changed_event_id FROM workflow_schedule_arrivals WHERE occurrence_id=$1)`, id).Scan(&journal); err != nil || !journal.Equal(*after.Arrival.Observed) {
		t.Fatal("observation is not the immutable database event instant", journal, err)
	}
}
