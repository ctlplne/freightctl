//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func scheduledCollectionFixture(t *testing.T) (*fixture, ScheduleSelection, time.Time) {
	t.Helper()
	f := setup(t)
	source := collectionTestSource()
	source.Contract = ScheduledCollectionContract
	source.Manifest = "settlement-{due_utc}.ready.json"
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d := f.definition()
	d.Source = &source
	d.Steps = d.Steps[:1]
	w := f.approved(t, d)
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	return f, ScheduleSelection{Name: "Expected remote settlement", Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Source: ScheduleSourceSelection{Directory: source.Directory, Pattern: source.Manifest, Kind: "sftp.collect"}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 4, MaxActive: 2, MaxFiles: source.MaxFiles, Deadline: 60, Grace: 1, ExpectedAuthority: 1, Arrival: &ScheduleArrivalSelection{LateAfter: 1, Deadline: 10, Poll: 1}}, due
}

func TestScheduledArrivalFrozenReadyAndCollectionHandoffKeepOriginalCutoffsAndReceipts(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	schedule := saveSchedule(t, f, x, "", 0, "frozen-ready")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "frozen-ready-due")
	id := tick.Occurrences[0].ID
	view, err := f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	proof := map[string]any{"occurrence": tick.Occurrences[0], "waiting": view}
	owner := secure.NewID()
	a, _, _, err := f.s.claimArrivalProbe(f.ctx, f.scope, id, view.Arrival.Hash, owner)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}}}
	_, hash, _ := digest(manifest)
	request := CollectionWorkRequest{Hash: a.Hash}
	_, meaning, _ := digest(struct {
		Kind, ID string
		Input    CollectionWorkRequest
	}{"probe_schedule_arrival", id, request})
	observed, err := f.s.finishArrivalProbe(f.scope, id, owner, a.Fence, "probe-ready-receipt", meaning, "ready", "verified_ready_manifest_observed", manifest, hash)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := f.s.ProbeScheduleArrival(f.ctx, f.scope, id, "probe-ready-receipt", request)
	if err != nil || !replayed.Replayed || !bytes.Equal(observed.Resource, replayed.Resource) {
		t.Fatal("ready response loss changed original probe receipt", err)
	}
	view, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || view.Arrival.State != "ready" || view.Arrival.JobID != nil || view.Arrival.Probes != 1 || view.Arrival.ManifestHash == nil || *view.Arrival.ManifestHash != hash {
		t.Fatal("ready observation started collection or lost its frozen manifest", view, err)
	}
	proof["ready"] = view
	decision := Decision{Hash: a.Hash, Revision: view.Arrival.Revision}
	queued, err := f.s.AdmitScheduleArrival(f.ctx, f.scope, id, "queue-ready-receipt", decision)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.AdmitScheduleArrival(f.ctx, f.scope, id, "queue-ready-receipt", decision)
	if err != nil || !again.Replayed || !bytes.Equal(queued.Resource, again.Resource) {
		t.Fatal("collection handoff receipt changed", err)
	}
	view, err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil || view.Collection == nil || view.Arrival.State != "admitted" || view.Arrival.Probes != 1 {
		t.Fatal(view, err)
	}
	proof["admitted"] = view
	job := view.Collection.Job
	frozen, err := collectionDefinition(job)
	if err != nil || frozen.Schedule == nil || frozen.Schedule.ManifestHash != hash || frozen.Schedule.ManifestName != "settlement-"+due.Format("20060102T150405Z")+".ready.json" || !job.Deadline.Equal(due.Add(time.Minute)) || job.Attempts != 0 {
		t.Fatal("collection changed due cutoff or reread-source budget", job, frozen, err)
	}
	// These calls supply a trusted read adapter result; native stock SFTP proof
	// separately exercises the actual source worker and its immutable file reads.
	ready, err := f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || !ready.WorkDue || ready.RouteReady {
		t.Fatal("new scheduled job is not ready for ordinary byte work", ready, err)
	}
	collector := secure.NewID()
	job, _, _, err = f.s.claimCollection(f.ctx, f.scope, job.ID, job.Hash, collector)
	if err != nil {
		t.Fatal(err)
	}
	ready, err = f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || ready.WorkDue || ready.RouteReady {
		t.Fatal("readiness bypassed original worker lease", ready, err)
	}
	if err = f.s.captureCollectionManifest(f.ctx, f.scope, job.ID, collector, job.Fence, manifest, hash); err != nil {
		t.Fatal(err)
	}
	collected, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := collected.Inputs[0]
	if _, _, err = f.s.Custody.Disk.StageGenerated(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, input.ObjectID), 3, func(w io.Writer) error { _, e := io.WriteString(w, "abc"); return e }); err != nil {
		t.Fatal(err)
	}
	if err = f.s.acceptCollectionInput(f.ctx, f.scope, job.ID, collector, job.Fence, &input); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.completeCollectionWork(f.ctx, f.scope, job.ID, collector, job.Fence, "finish-scheduled-source", secure.Digest([]byte("finish-scheduled-source"))); err != nil {
		t.Fatal(err)
	}
	collected, err = f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	ready, err = f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || ready.WorkDue || !ready.RouteReady {
		t.Fatal("published captured input did not reach ordinary routing readiness", ready, err)
	}
	if _, err = f.s.RefreshCollection(f.ctx, f.scope, job.ID, "queue-scheduled-forwarding", Decision{Hash: job.Hash, Revision: collected.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	collected, err = f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || collected.Inputs[0].RunID == nil {
		t.Fatal(collected, err)
	}
	ready, err = f.s.CollectionReady(f.ctx, f.scope, job.ID)
	if err != nil || ready.WorkDue || ready.RouteReady {
		t.Fatal("already routed input would create empty poll receipts", ready, err)
	}
	proof["captured"], err = f.s.ScheduleArrivalStatus(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.s.Status(f.ctx, f.scope, *collected.Inputs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.s.ScheduleStatus(f.ctx, f.scope, schedule.ID, schedule.Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ControlSchedule(f.ctx, f.scope, schedule.ID, schedule.Version, "suspend", "suspend-source-calendar", Decision{Hash: schedule.Hash, Revision: live.Schedule.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, status.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrCollection) {
		t.Fatal("suspended calendar still authorized ordinary source forwarding", err)
	}
	_, body, err := f.s.Custody.DownloadPath(f.ctx, f.scope, input.Target)
	if err != nil {
		t.Fatal("calendar suspension recalled already captured local bytes", err)
	}
	body.Close()
	if ref := os.Getenv("FREIGHTCTL_WRITE_ARRIVAL_FIXTURE"); ref != "" {
		data, e := json.MarshalIndent(proof, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		out, e := os.OpenFile(ref, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = out.Write(append(data, '\n')); e != nil {
			out.Close()
			t.Fatal(e)
		}
		if e = out.Close(); e != nil {
			t.Fatal(e)
		}
	}
}

func TestScheduledArrivalSQLRefusesNullProducerSchemaBeforeClaimingReady(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	schedule := saveSchedule(t, f, x, "", 0, "null-ready-schema")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "null-ready-due")
	id := tick.Occurrences[0].ID
	read, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	a, err := read.ScheduleArrival(f.ctx, id, false)
	read.Tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, _, _, err = f.s.claimArrivalProbe(f.ctx, f.scope, id, a.Hash, secure.NewID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.arrivalBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	malformed := map[string]any{"schema_version": nil, "batch_id": secure.NewID(), "files": []map[string]any{{"name": "one.csv", "size_bytes": 3, "sha256": secure.Digest([]byte("abc"))}}}
	encoded, err := json.Marshal(malformed)
	if err != nil {
		t.Fatal(err)
	}
	hash := secure.Digest(encoded)
	previous := a.Revision
	a.Revision++
	a.State = "ready"
	a.Owner = ""
	a.Until = nil
	a.Manifest = encoded
	a.ManifestHash = &hash
	a.Observed = &now
	a.Reason = "invented_ready_observation"
	err = tx.SaveScheduleArrival(f.ctx, a, previous)
	if err == nil {
		err = tx.Tx.Commit(f.ctx)
	}
	collectionSQLRefusal(t, err)
}
func TestScheduledCollectionDueDecisionCreatesOnlyExactArrivalIntent(t *testing.T) {
	f, x, due := scheduledCollectionFixture(t)
	preview, err := f.s.PreviewSchedule(f.ctx, f.scope, x)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Definition.Collection == nil || preview.ExternalContact || preview.Definition.Source.Regex != "" {
		t.Fatal("remote source became a local folder selector", preview)
	}
	schedule := saveSchedule(t, f, x, "", 0, "remote-calendar")
	waitSchedule(t, f, due)
	_, tick := tickSchedule(t, f, schedule, "remote-due")
	if len(tick.Occurrences) != 1 || tick.Occurrences[0].Kind != "collection" || len(tick.RunIDs) != 0 {
		t.Fatal("due decision did not preserve separate arrival stage", tick)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	arrival, err := tx.ScheduleArrival(f.ctx, tick.Occurrences[0].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := arrivalBinding(arrival)
	if err != nil {
		t.Fatal(err)
	}
	if arrival.State != "waiting" || arrival.Probes != 0 || arrival.JobID != nil || len(arrival.Manifest) != 0 || binding.Manifest != "settlement-"+due.Format("20060102T150405Z")+".ready.json" || !binding.Due.Equal(due) || !binding.Deadline.Equal(due.Add(time.Minute)) {
		t.Fatal("arrival invented source contact or changed due identity", arrival, binding)
	}
	var count int
	if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_collection_jobs)+(SELECT count(*) FROM workflow_runs)+(SELECT count(*) FROM delivery_intents)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("metadata-only due decision started a byte job or transfer", count, err)
	}
}
