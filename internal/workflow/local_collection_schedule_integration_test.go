//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

func localCalendarFixture(t *testing.T) (localCollectionSetup, store.ScheduleSummary, time.Time, *CollectionManifest) {
	t.Helper()
	x := newLocalCollection(t)
	x.source.Contract, x.source.Manifest = ScheduledCollectionContract, "settlement-{due_utc}.ready.json"
	w := x.f.approved(t, Definition{Schema: 1, Name: "Reviewed local producer calendar", Steps: []Step{}, Source: &x.source})
	x.selection.Workflow = Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}
	due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: int64(len(x.body)), SHA256: secure.Digest(x.body)}}}
	raw, _, err := digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Replace(x.source.Manifest, "{due_utc}", due.Format("20060102T150405Z"), 1)
	writeLocalCollectionFixture(t, filepath.Join(x.directory, name), raw)
	selection := ScheduleSelection{Name: "Expected local producer settlement", Workflow: x.selection.Workflow, Source: ScheduleSourceSelection{Directory: x.source.Directory, Pattern: x.source.Manifest, Kind: x.source.Kind}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 2, MaxActive: 1, MaxFiles: x.source.MaxFiles, Deadline: 60, Grace: 1, ExpectedAuthority: x.selection.Authority, Arrival: &ScheduleArrivalSelection{LateAfter: 0, Deadline: 30, Poll: 1}}
	if _, err = x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection); !errors.Is(err, ErrInput) {
		t.Fatal("manual admission bypassed local calendar due manifest", err)
	}
	preview, err := x.f.s.PreviewSchedule(x.f.ctx, x.f.scope, selection)
	if err != nil || preview.ExternalContact || !preview.ApprovalRequired || preview.Definition.Collection == nil || preview.Definition.Collection.Connection.Local == nil || !reflect.DeepEqual(preview.Definition.Collection.Source, x.source) || len(preview.Effects) != 0 {
		t.Fatal("local calendar preview changed read-only source or authority", err)
	}
	out, err := x.f.s.DraftSchedule(x.f.ctx, x.f.scope, "local-calendar-draft", ScheduleDraftRequest{Selection: selection, Hash: preview.Hash})
	var resource ScheduleResource
	if err != nil || json.Unmarshal(out.Resource, &resource) != nil || resource.Schedule.Hash != preview.Hash {
		t.Fatal("exact local calendar draft receipt", err)
	}
	out, err = x.f.s.ControlSchedule(x.f.ctx, x.f.scope, resource.Schedule.ID, resource.Schedule.Version, "activate", "local-calendar-activate", Decision{Hash: resource.Schedule.Hash, Revision: resource.Schedule.Revision})
	if err != nil || json.Unmarshal(out.Resource, &resource) != nil || resource.Schedule.State != "active" || resource.Schedule.Hash != preview.Hash {
		t.Fatal("exact local calendar approval", err)
	}
	return x, resource.Schedule, due, manifest
}

func readyLocalCalendar(t *testing.T, x localCollectionSetup, schedule store.ScheduleSummary, due time.Time) (string, *ScheduleArrivalView) {
	t.Helper()
	waitSchedule(t, x.f, due)
	_, tick := tickSchedule(t, x.f, schedule, "local-calendar-due")
	if len(tick.Occurrences) != 1 {
		t.Fatal("local calendar duplicated its due occurrence")
	}
	id := tick.Occurrences[0].ID
	arrival, err := x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	request := CollectionWorkRequest{Hash: arrival.Arrival.Hash}
	first, err := x.f.s.ProbeScheduleArrival(x.f.ctx, x.f.scope, id, "local-calendar-probe", request)
	if err != nil {
		t.Fatal("actual local producer manifest probe", err)
	}
	name := strings.Replace(x.source.Manifest, "{due_utc}", due.Format("20060102T150405Z"), 1)
	if err = os.Remove(filepath.Join(x.directory, name)); err != nil {
		t.Fatal(err)
	}
	again, err := x.f.s.ProbeScheduleArrival(x.f.ctx, x.f.scope, id, "local-calendar-probe", request)
	if err != nil || !again.Replayed || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal("saved local probe receipt reread the removed manifest", err)
	}
	arrival, err = x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
	if err != nil || arrival.Arrival.State != "ready" || arrival.Arrival.ManifestHash == nil || arrival.Collection != nil {
		t.Fatal("local ready probe copied payload or lost manifest", err)
	}
	return id, arrival
}

func TestLocalCalendarCapturesFrozenDueManifestWithoutForwardingOrRereading(t *testing.T) {
	x, schedule, due, manifest := localCalendarFixture(t)
	id, arrival := readyLocalCalendar(t, x, schedule, due)
	decision := Decision{Hash: arrival.Arrival.Hash, Revision: arrival.Arrival.Revision}
	first, err := x.f.s.AdmitScheduleArrival(x.f.ctx, x.f.scope, id, "local-calendar-admit", decision)
	if err != nil {
		t.Fatal(err)
	}
	again, err := x.f.s.AdmitScheduleArrival(x.f.ctx, x.f.scope, id, "local-calendar-admit", decision)
	if err != nil || !again.Replayed || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal("local calendar admission replay changed original receipt", err)
	}
	arrival, err = x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
	if err != nil || arrival.Collection == nil {
		t.Fatal("local ready manifest did not admit a collection", err)
	}
	job := arrival.Collection.Job
	frozen, err := collectionDefinition(job)
	_, hash, _ := digest(manifest)
	if err != nil || frozen.SourceIdentity != collectionSourceIdentity(x.connection) || frozen.Schedule == nil || frozen.Schedule.OccurrenceID != id || !frozen.Schedule.Due.Equal(due) || frozen.Schedule.ManifestHash != hash || job.Manifest != nil || job.Attempts != 0 || job.Fence != 0 || !job.Deadline.Equal(due.Add(time.Minute)) {
		t.Fatal("local due occurrence lost exact root,manifest,cutoff or no-copy admission", err)
	}
	snapshot, gotHash, err := x.f.s.scheduledCollectionManifest(x.f.ctx, x.f.scope, frozen)
	if err != nil || !reflect.DeepEqual(snapshot, manifest) || gotHash != hash {
		t.Fatal("local schedule lost independently published frozen manifest", err)
	}
	before := localCollectionCounts(t, x.f)
	worked, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "local-calendar-work", CollectionWorkRequest{Hash: job.Hash})
	if err != nil {
		t.Fatal(err)
	}
	view, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
	if err != nil || !view.Job.Captured || view.Job.State != "captured" || view.Job.Attempts != 1 || view.Job.Fence != 1 || len(view.Inputs) != 1 || view.Inputs[0].FileID == nil || view.Inputs[0].RunID != nil || view.BusinessAcceptance != "unknown" {
		t.Fatal("local calendar capture differs", err)
	}
	file, stream, err := x.f.s.Custody.DownloadPath(x.f.ctx, x.f.scope, view.Inputs[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(x.body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, x.body) || file.ID != *view.Inputs[0].FileID || file.SHA256 != secure.Digest(x.body) {
		t.Fatal("local calendar independent custody readback differs", err)
	}
	after := localCollectionCounts(t, x.f)
	if after[0] != before[0]+1 || after[1] != before[1] || after[2] != before[2] {
		t.Fatal("local calendar capture gained sending/execution authority", before, after)
	}
	if err = os.Remove(x.configuration); err != nil {
		t.Fatal(err)
	}
	again, err = x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "local-calendar-work", CollectionWorkRequest{Hash: job.Hash})
	if err != nil || !again.Replayed || !bytes.Equal(worked.Resource, again.Resource) || localCollectionCounts(t, x.f) != after {
		t.Fatal("saved local calendar capture reopened source or repeated effects", err)
	}
	if got, err := os.ReadFile(filepath.Join(x.directory, "one.csv")); err != nil || !bytes.Equal(got, x.body) {
		t.Fatal("local calendar changed producer bytes", err)
	}
}

func TestLocalCalendarChangedPhysicalRootCannotAdoptFrozenReadyManifest(t *testing.T) {
	x, schedule, due, _ := localCalendarFixture(t)
	id, arrival := readyLocalCalendar(t, x, schedule, due)
	if err := os.Rename(x.directory, x.directory+"-retained"); err != nil {
		t.Fatal(err)
	}
	if err := protectedfs.EnsureDirectory(x.directory); err != nil {
		t.Fatal(err)
	}
	writeLocalCollectionFixture(t, filepath.Join(x.directory, "one.csv"), x.body)
	if _, err := x.f.s.AdmitScheduleArrival(x.f.ctx, x.f.scope, id, "changed-local-calendar-admit", Decision{Hash: arrival.Arrival.Hash, Revision: arrival.Arrival.Revision}); err != nil {
		t.Fatal(err)
	}
	arrival, err := x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
	if err != nil || arrival.Collection == nil {
		t.Fatal(err)
	}
	job := arrival.Collection.Job
	before := localCollectionCounts(t, x.f)
	if _, err = x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "changed-local-calendar-work", CollectionWorkRequest{Hash: job.Hash}); err != nil {
		t.Fatal(err)
	}
	view, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
	if err != nil || view.Job.Captured || view.Job.State != "retry" || len(view.Inputs) != 0 {
		t.Fatal("replacement local root adopted a reviewed occurrence", err)
	}
	after := localCollectionCounts(t, x.f)
	if after[0] != before[0] || after[1] != before[1] || after[2] != before[2] {
		t.Fatal("replaced calendar root created custody or sends", before, after)
	}
}

func TestLocalConnectionRuntimeSQLAdmitsOnlyExactReadOnlySourceShape(t *testing.T) {
	x := newLocalCollection(t)
	tx, err := x.f.s.Custody.DB.Begin(x.f.ctx, x.f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(x.f.ctx)
	original, err := tx.Configuration(x.f.ctx, true, x.connection.ID, x.connection.Version, false)
	if err != nil {
		t.Fatal(err)
	}
	for index, mutate := range []func(map[string]any){nil,
		func(d map[string]any) { d["schema_version"] = 1 },
		func(d map[string]any) { d["directory"] = "/other" },
		func(d map[string]any) { d["local"].(map[string]any)["execute"] = true },
		func(d map[string]any) { d["local"].(map[string]any)["schema_version"] = 2 },
		func(d map[string]any) { d["local"].(map[string]any)["root_fingerprint"] = "unknown" },
		func(d map[string]any) { d["ftps"] = map[string]any{} },
	} {
		var value map[string]any
		if err = json.Unmarshal(original.Definition, &value); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(value)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		forged := *original
		forged.ID = secure.NewID()
		if index != 0 {
			forged.Definition, forged.Hash = raw, secure.Digest(raw)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "SAVEPOINT local_connection_forgery"); err != nil {
			t.Fatal(err)
		}
		// SaveConfiguration creates the matching immutable event first. These
		// tests exercise actual runtime DML guards,not a missing-journal refusal.
		err = tx.SaveConfiguration(x.f.ctx, true, &forged, 0)
		if index == 0 {
			if err != nil {
				t.Fatal("matching-event exact local connection control refused", err)
			}
		} else {
			collectionSQLRefusal(t, err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "ROLLBACK TO SAVEPOINT local_connection_forgery"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "RELEASE SAVEPOINT local_connection_forgery"); err != nil {
			t.Fatal(err)
		}
	}
}
