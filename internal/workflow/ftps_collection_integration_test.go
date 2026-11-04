//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/calendar"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type ftpsCollectionSetup struct {
	f, producer *fixture
	connection  ConnectionView
	source      CollectionSource
	workflow    Reference
	selection   CollectionSelection
	listener    *replyLossListener
}

func newFTPSCollection(t *testing.T, implicit, program, scheduled bool) ftpsCollectionSetup {
	t.Helper()
	f := setup(t)
	producer, spec, listener := governedFTPSReceiver(t, implicit)
	connection := registeredFTPSConnection(t, f, spec)
	source := collectionTestSource()
	source.Kind, source.Directory = "ftps.collect", "/"
	source.Connection = Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}
	if scheduled {
		source.Contract, source.Manifest = ScheduledCollectionContract, "settlement-{due_utc}.ready.json"
	}
	d := Definition{Schema: 1, Name: "Read-only FTPS settlement", Steps: []Step{}, Source: &source}
	if program {
		d.Schema = 2
		d.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "reviewed_local_collection"}}}
	}
	preview, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: d})
	if err != nil || preview.ExternalContact || preview.Collection == nil || preview.Collection.Kind != source.Kind || preview.Collection.Connection.Protocol != "ftps" || listener.contacts.Load() != 0 {
		t.Fatal("FTPS source metadata contacted a peer or lost its transport", err)
	}
	w := f.approved(t, d)
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	authority := tx.AuthorityRevision
	tx.Tx.Rollback(f.ctx)
	ref := Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}
	return ftpsCollectionSetup{f, producer, connection, source, ref, CollectionSelection{Workflow: ref, Timeout: 120, Authority: authority}, listener}
}

func publishFTPSCollectionObject(t *testing.T, x ftpsCollectionSetup, name string, body []byte) *store.File {
	t.Helper()
	file, _, err := x.producer.s.Custody.AcceptAt(x.producer.ctx, x.producer.scope, secure.NewID(), int64(len(body)), secure.Digest(body), bytes.NewReader(body), custody.UploadTarget{Path: path.Join("/inbox", name)})
	if err != nil {
		t.Fatal("producer durable object", err)
	}
	return file
}

func publishFTPSCollectionManifest(t *testing.T, x ftpsCollectionSetup, name string, files []CollectionFile) *CollectionManifest {
	t.Helper()
	m := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: files}
	raw, _, err := digest(m)
	if err != nil {
		t.Fatal(err)
	}
	publishFTPSCollectionObject(t, x, name, raw)
	return m
}

func requireCollectedFTPSBytes(t *testing.T, x ftpsCollectionSetup, job string, expected []byte) *CollectionView {
	t.Helper()
	v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job)
	if err != nil || !v.Current || v.Job.State != "captured" || !v.Job.Captured || len(v.Inputs) != 1 || v.BusinessAcceptance != "unknown" {
		t.Fatal("FTPS batch not exactly captured", err)
	}
	i := v.Inputs[0]
	file, stream, err := x.f.s.Custody.DownloadPath(x.f.ctx, x.f.scope, i.Target)
	if err != nil {
		t.Fatal("captured local namespace unavailable", err)
	}
	body, err := io.ReadAll(io.LimitReader(stream, int64(len(expected))+1))
	stream.Close()
	if err != nil || !bytes.Equal(body, expected) || file.ID != i.ObjectID || i.FileID == nil || *i.FileID != file.ID || file.SHA256 != secure.Digest(expected) || file.Size != int64(len(expected)) {
		t.Fatal("independent local readback or immutable revision differs", err)
	}
	return v
}

func TestFTPSCollectionCopiesExactSourceAndReplaysWithoutAnotherContact(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		for _, program := range []bool{false, true} {
			t.Run(fmt.Sprintf("implicit-%t/program-%t", implicit, program), func(t *testing.T) {
				x := newFTPSCollection(t, implicit, program, false)
				body := []byte("abc")
				original := publishFTPSCollectionObject(t, x, "one.csv", body)
				manifest := publishFTPSCollectionManifest(t, x, x.source.Manifest, []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest(body)}})
				job, first := startCollection(t, x.f, x.selection, "ftps-collect-start")
				if x.listener.contacts.Load() != 0 || job.Attempts != 0 || job.Fence != 0 || job.Manifest != nil {
					t.Fatal("queue or preview performed source work")
				}
				request := CollectionWorkRequest{Hash: job.Hash}
				worked, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "ftps-collect-worker", request)
				if err != nil {
					t.Fatal("actual FTPS collector", err)
				}
				v := requireCollectedFTPSBytes(t, x, job.ID, body)
				_, expectedHash, _ := digest(manifest)
				if v.Job.Attempts != 1 || v.Job.Fence != 1 || v.Job.ManifestHash == nil || *v.Job.ManifestHash != expectedHash || v.Inputs[0].FileID == nil || *v.Inputs[0].FileID == original.ID {
					t.Fatal("source batch/fence or separate local custody identity differs")
				}
				contacts := x.listener.contacts.Load()
				again, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "ftps-collect-worker", request)
				if err != nil || !again.Replayed || !bytes.Equal(again.Resource, worked.Resource) || x.listener.contacts.Load() != contacts {
					t.Fatal("saved worker key repeated source reads", err)
				}
				preview, err := x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection)
				if err != nil {
					t.Fatal(err)
				}
				again, err = x.f.s.StartCollection(x.f.ctx, x.f.scope, "ftps-collect-start", CollectionStartRequest{Selection: x.selection, Hash: preview.Hash})
				if err != nil || !again.Replayed || !bytes.Equal(again.Resource, first.Resource) || x.listener.contacts.Load() != contacts {
					t.Fatal("saved admission key changed the original receipt", err)
				}
				if got := readReceiverBytes(t, x.producer, "/inbox/one.csv"); !bytes.Equal(got, body) {
					t.Fatal("read-only collector changed source bytes")
				}
				if _, err = x.f.s.Run(x.f.ctx, x.f.scope, "inject-uncollected-file", RunRequest{Workflow: x.workflow, FileID: x.f.file.ID}); !errors.Is(err, ErrInput) {
					t.Fatal("manual file bypassed FTPS source lineage", err)
				}
				if program {
					if _, err = x.f.s.RefreshCollection(x.f.ctx, x.f.scope, job.ID, "admit-collected-ftps-local-plan", Decision{Hash: job.Hash, Revision: v.Job.Revision}); err != nil {
						t.Fatal(err)
					}
					local, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
					if err != nil || len(local.Inputs) != 1 || local.Inputs[0].RunID == nil {
						t.Fatal("collected FTPS program did not admit its owned input", err)
					}
					run, err := x.f.s.Status(x.f.ctx, x.f.scope, *local.Inputs[0].RunID)
					if err != nil || run.Run.State != "kept_local" || run.Run.FileID != *v.Inputs[0].FileID || len(run.Steps) != 0 || x.listener.contacts.Load() != contacts {
						t.Fatal("local FTPS collection plan changed source or made a remote effect", err)
					}
					plan, err := storedExecutionPlan(run.Run)
					if err != nil || plan == nil || plan.LocalReason != "reviewed_local_collection" || len(plan.Steps) != 0 {
						t.Fatal("local outcome lost its immutable compiled plan", err)
					}
				}
			})
		}
	}
}

func TestFTPSCollectionMismatchCannotPublishAnAcceptedSibling(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprint(implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, false)
			publishFTPSCollectionObject(t, x, "one.csv", []byte("abc"))
			publishFTPSCollectionObject(t, x, "two.csv", []byte("def"))
			publishFTPSCollectionManifest(t, x, x.source.Manifest, []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}, {Name: "two.csv", Size: 3, SHA256: secure.Digest([]byte("xyz"))}})
			job, _ := startCollection(t, x.f, x.selection, "mismatching-ftps-batch")
			if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "mismatching-worker", CollectionWorkRequest{Hash: job.Hash}); err != nil {
				t.Fatal(err)
			}
			v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
			if err != nil || v.Job.Captured || v.Job.State != "retry" || v.Job.Reason != "source_file_verification_or_capacity_failed" || len(v.Inputs) != 2 || v.Inputs[0].State != "accepted" || v.Inputs[1].State != "pending" {
				t.Fatal("mismatched FTPS payload lost exact partial-batch state", err)
			}
			_, stream, err := x.f.s.Custody.Download(x.f.ctx, x.f.scope, v.Inputs[0].ObjectID)
			if stream != nil {
				stream.Close()
			}
			if !errors.Is(err, store.ErrState) {
				t.Fatal("uncompleted FTPS batch exposed a sealed sibling", err)
			}
			if _, err = x.f.s.Custody.StatPath(x.f.ctx, x.f.scope, v.Inputs[0].Target); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("uncompleted FTPS batch published a path", err)
			}
		})
	}
}

func TestFTPSCollectionProducerBatchCannotDuplicateOrChangeItsCapturedMeaning(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprint(implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, false)
			body := []byte("abc")
			publishFTPSCollectionObject(t, x, "one.csv", body)
			manifest := publishFTPSCollectionManifest(t, x, x.source.Manifest, []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest(body)}})
			first, _ := startCollection(t, x.f, x.selection, "original-ftps-batch")
			if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, first.ID, "capture-original-ftps-batch", CollectionWorkRequest{Hash: first.Hash}); err != nil {
				t.Fatal(err)
			}
			captured := requireCollectedFTPSBytes(t, x, first.ID, body)
			duplicate, _ := startCollection(t, x.f, x.selection, "same-ftps-batch-new-job")
			if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, duplicate.ID, "observe-same-ftps-batch", CollectionWorkRequest{Hash: duplicate.Hash}); err != nil {
				t.Fatal(err)
			}
			v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, duplicate.ID)
			if err != nil || !v.Job.Captured || !reflect.DeepEqual(v.Inputs, captured.Inputs) {
				t.Fatal("repeated producer batch replaced accepted custody or original ownership", err)
			}
			// The producer can publish another immutable namespace revision. Its
			// old batch ID still cannot authorize a different payload manifest.
			publishFTPSCollectionObject(t, x, "two.csv", []byte("def"))
			if _, err = x.producer.s.Custody.PathCommand(x.producer.ctx, x.producer.scope, secure.NewID(), store.PathCommand{Operation: "remove", Path: path.Join("/inbox", x.source.Manifest)}); err != nil {
				t.Fatal(err)
			}
			changed := *manifest
			changed.Files = []CollectionFile{{Name: "two.csv", Size: 3, SHA256: secure.Digest([]byte("def"))}}
			raw, _, _ := digest(changed)
			publishFTPSCollectionObject(t, x, x.source.Manifest, raw)
			forged, _ := startCollection(t, x.f, x.selection, "changed-ftps-batch-meaning")
			if _, err = x.f.s.WorkCollection(x.f.ctx, x.f.scope, forged.ID, "refuse-changed-ftps-batch", CollectionWorkRequest{Hash: forged.Hash}); err != nil {
				t.Fatal(err)
			}
			v, err = x.f.s.CollectionStatus(x.f.ctx, x.f.scope, forged.ID)
			if err != nil || v.Job.Captured || v.Job.State != "attention" || v.Job.Reason != "producer_batch_binding_refused" || v.Job.Manifest != nil || len(v.Inputs) != 0 {
				t.Fatal("changed producer batch became accepted input authority", err)
			}
			if original := requireCollectedFTPSBytes(t, x, first.ID, body); !reflect.DeepEqual(original.Job, captured.Job) || !reflect.DeepEqual(original.Inputs, captured.Inputs) {
				t.Fatal("refused batch altered original immutable history")
			}
		})
	}
}

func TestFTPSCollectionRevocationFencesOriginalWorkerBeforeContact(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprint(implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, false)
			job, _ := startCollection(t, x.f, x.selection, "revoke-ftps-source")
			if _, err := x.f.s.RevokeConnection(x.f.ctx, x.f.scope, x.connection.ID, x.connection.Version, "revoke-exact-ftps", Decision{Hash: x.connection.Hash, Revision: x.connection.Revision}); err != nil {
				t.Fatal(err)
			}
			if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "original-source-worker", CollectionWorkRequest{Hash: job.Hash}); !errors.Is(err, store.ErrCollection) {
				t.Fatal("revoked FTPS source reached a worker", err)
			}
			v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
			if err != nil || v.Current || v.Observed != "attention" || !reflect.DeepEqual(v.Job, job) || x.listener.contacts.Load() != 0 {
				t.Fatal("revocation changed an untouched job or contacted its source", err)
			}
		})
	}
}

func TestFTPSCollectionRuntimeSQLRejectsDetachedProtocolAndPeerViews(t *testing.T) {
	x := newFTPSCollection(t, false, false, false)
	preview, err := x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := startCollection(t, x.f, x.selection, "exact-ftps-sql-control")
	tx, err := x.f.s.Custody.DB.Begin(x.f.ctx, x.f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(x.f.ctx)
	for index, mutate := range []func(map[string]any){
		nil,
		func(d map[string]any) { d["source"].(map[string]any)["kind"] = "sftp.collect" },
		func(d map[string]any) { delete(d["source_connection"].(map[string]any), "protocol") },
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["host_fingerprint"] = "SHA256:" + strings.Repeat("a", 43)
		},
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["ftps"].(map[string]any)["mode"] = "implicit"
		},
		func(d map[string]any) { d["source_connection"].(map[string]any)["address"] = "127.0.0.1:2990" },
		func(d map[string]any) {
			d["source"].(map[string]any)["connection"].(map[string]any)["authority"] = "invented"
		},
	} {
		raw, _ := json.Marshal(preview.Definition)
		var value map[string]any
		json.Unmarshal(raw, &value)
		if mutate != nil {
			mutate(value)
		}
		raw, _ = json.Marshal(value)
		var current bool
		if err = tx.Tx.QueryRow(x.f.ctx, `SELECT freightctl_collection_definition_current($1,$2,$3,$4)`, x.f.scope.Tenant, x.f.scope.Partner, tx.Actor, raw).Scan(&current); err != nil || current != (index == 0) {
			t.Fatal("runtime SQL accepted a detached source/view or rejected exact metadata", index, err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "SAVEPOINT ftps_collection_forgery"); err != nil {
			t.Fatal(err)
		}
		forged := *base
		forged.ID, forged.Definition, forged.Hash = secure.NewID(), raw, secure.Digest(raw)
		if index == 0 {
			forged.Definition, forged.Hash = base.Definition, base.Hash
		}
		forged.Created, err = tx.DatabaseTime(x.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		forged.Next, forged.Deadline = forged.Created, forged.Created.Add(120*time.Second)
		// SaveCollection appends the correctly matching event before DML.
		// The refusal must therefore come from source/view authority rather
		// than an absent or detached journal event. The exact control must pass.
		err = tx.SaveCollection(x.f.ctx, &forged, 0)
		if index == 0 {
			if err != nil {
				t.Fatal("matching-event exact SQL control failed", err)
			}
		} else {
			collectionSQLRefusal(t, err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "ROLLBACK TO SAVEPOINT ftps_collection_forgery"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "RELEASE SAVEPOINT ftps_collection_forgery"); err != nil {
			t.Fatal(err)
		}
	}
	if x.listener.contacts.Load() != 0 {
		t.Fatal("SQL metadata predicates contacted a source")
	}
}

func saveFTPSCollectionSchedule(t *testing.T, x ftpsCollectionSetup, selection ScheduleSelection) store.ScheduleSummary {
	t.Helper()
	f := x.f
	p, err := f.s.PreviewSchedule(f.ctx, f.scope, selection)
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := digest(p.Definition)
	if err != nil || hash != p.Hash || p.ExternalContact || !p.ApprovalRequired || len(p.Effects) != 0 || len(p.Definition.Calendar.Rules) == 0 || p.Definition.Collection == nil || !reflect.DeepEqual(p.Definition.Collection.Source, x.source) || !reflect.DeepEqual(p.Definition.Collection.Connection, x.connection) || x.listener.contacts.Load() != 0 {
		t.Fatal("exact local-only FTPS schedule preview required", err)
	}
	// The existing saveSchedule helper intentionally asserts one outgoing
	// recipient. This source-only contract must instead prove zero recipients
	// and the complete exact reviewed source, without changing that helper.
	out, err := f.s.DraftSchedule(f.ctx, f.scope, "scheduled-ftps", ScheduleDraftRequest{Selection: selection, Hash: p.Hash})
	var resource ScheduleResource
	if err != nil || json.Unmarshal(out.Resource, &resource) != nil || resource.Kind != "workflow_schedule" || resource.Schedule.Hash != p.Hash {
		t.Fatal("exact FTPS schedule draft receipt", err)
	}
	out, err = f.s.ControlSchedule(f.ctx, f.scope, resource.Schedule.ID, resource.Schedule.Version, "activate", "scheduled-ftps-activate", Decision{Hash: resource.Schedule.Hash, Revision: resource.Schedule.Revision})
	if err != nil || json.Unmarshal(out.Resource, &resource) != nil || resource.Schedule.State != "active" || resource.Schedule.Hash != p.Hash || x.listener.contacts.Load() != 0 {
		t.Fatal("exact no-contact FTPS schedule activation", err)
	}
	return resource.Schedule
}

func TestScheduledFTPSCollectionUsesFrozenDueManifestAndOriginalReceipts(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprint(implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, true)
			publishFTPSCollectionObject(t, x, "one.csv", []byte("abc"))
			due := time.Now().UTC().Truncate(time.Second).Add(2 * time.Second)
			name := strings.Replace(x.source.Manifest, "{due_utc}", due.Format("20060102T150405Z"), 1)
			publishFTPSCollectionManifest(t, x, name, []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}})
			selection := ScheduleSelection{Name: "Expected FTPS settlement", Workflow: x.workflow, Source: ScheduleSourceSelection{Directory: x.source.Directory, Pattern: x.source.Manifest, Kind: x.source.Kind}, Calendar: calendar.Selection{Zone: "UTC", Start: due, End: due.Add(time.Minute), Times: []string{due.Format("15:04:05")}, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Holidays: []string{}, Gap: "skip", Fold: "both"}, Missed: "all", CatchUp: 2, MaxActive: 1, MaxFiles: x.source.MaxFiles, Deadline: 60, Grace: 1, ExpectedAuthority: x.selection.Authority, Arrival: &ScheduleArrivalSelection{LateAfter: 0, Deadline: 30, Poll: 1}}
			if _, err := x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection); !errors.Is(err, ErrInput) {
				t.Fatal("manual admission bypassed a scheduled FTPS source", err)
			}
			schedule := saveFTPSCollectionSchedule(t, x, selection)
			waitSchedule(t, x.f, due)
			_, tick := tickSchedule(t, x.f, schedule, "scheduled-ftps-due")
			if len(tick.Occurrences) != 1 || x.listener.contacts.Load() != 0 {
				t.Fatal("calendar admission contacted FTPS or changed due occurrence")
			}
			id := tick.Occurrences[0].ID
			arrival, err := x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
			if err != nil {
				t.Fatal(err)
			}
			request := CollectionWorkRequest{Hash: arrival.Arrival.Hash}
			first, err := x.f.s.ProbeScheduleArrival(x.f.ctx, x.f.scope, id, "scheduled-ftps-probe", request)
			if err != nil {
				t.Fatal("actual FTPS manifest probe", err)
			}
			contacts := x.listener.contacts.Load()
			again, err := x.f.s.ProbeScheduleArrival(x.f.ctx, x.f.scope, id, "scheduled-ftps-probe", request)
			if err != nil || !again.Replayed || !bytes.Equal(first.Resource, again.Resource) || x.listener.contacts.Load() != contacts {
				t.Fatal("scheduled probe replay contacted source", err)
			}
			arrival, err = x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
			if err != nil || arrival.Arrival.State != "ready" || arrival.Arrival.ManifestHash == nil || arrival.Collection != nil {
				t.Fatal("ready probe copied payloads or lost frozen manifest", err)
			}
			if _, err = x.producer.s.Custody.PathCommand(x.producer.ctx, x.producer.scope, secure.NewID(), store.PathCommand{Operation: "remove", Path: path.Join("/inbox", name)}); err != nil {
				t.Fatal("producer manifest removal", err)
			}
			decision := Decision{Hash: arrival.Arrival.Hash, Revision: arrival.Arrival.Revision}
			admitted, err := x.f.s.AdmitScheduleArrival(x.f.ctx, x.f.scope, id, "scheduled-ftps-admit", decision)
			if err != nil {
				t.Fatal(err)
			}
			again, err = x.f.s.AdmitScheduleArrival(x.f.ctx, x.f.scope, id, "scheduled-ftps-admit", decision)
			if err != nil || !again.Replayed || !bytes.Equal(admitted.Resource, again.Resource) || x.listener.contacts.Load() != contacts {
				t.Fatal("scheduled handoff replay changed contact or receipt", err)
			}
			arrival, err = x.f.s.ScheduleArrivalStatus(x.f.ctx, x.f.scope, id)
			if err != nil || arrival.Collection == nil {
				t.Fatal(err)
			}
			job := arrival.Collection.Job
			if job.Manifest == nil || !job.Deadline.Equal(due.Add(time.Minute)) {
				t.Fatal("arrival lost exact manifest or original cutoff")
			}
			if _, err = x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "scheduled-ftps-worker", CollectionWorkRequest{Hash: job.Hash}); err != nil {
				t.Fatal(err)
			}
			requireCollectedFTPSBytes(t, x, job.ID, []byte("abc"))
		})
	}
}
