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

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

type localCollectionSetup struct {
	f                        *fixture
	directory, configuration string
	connection               ConnectionView
	source                   CollectionSource
	selection                CollectionSelection
	body, manifest           []byte
}

func writeLocalCollectionFixture(t *testing.T, name string, body []byte) {
	t.Helper()
	f, err := protectedfs.CreateExclusive(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}

func newLocalCollection(t *testing.T) localCollectionSetup {
	t.Helper()
	f := setup(t)
	directory := filepath.Join(t.TempDir(), "producer")
	if err := protectedfs.EnsureDirectory(directory); err != nil {
		t.Fatal(err)
	}
	identity, err := delivery.InspectLocalCollectionRoot(f.ctx, directory, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(filepath.Dir(directory), "local-source.json")
	raw, err := json.Marshal(map[string]any{"schema_version": 1, "profile": delivery.LocalCollectionProfile, "directory": directory, "root_fingerprint": identity})
	if err != nil {
		t.Fatal(err)
	}
	writeLocalCollectionFixture(t, configuration, raw)
	registered, err := f.s.RegisterConnection(f.ctx, f.scope, "register-private-local-source", ConnectionRequest{Directory: "/", Local: &delivery.LocalCollectionSource{Schema: 1, Reference: configuration, SHA256: secure.Digest(raw), RootFingerprint: identity}})
	if err != nil {
		t.Fatal("ordinary local connection registration", err)
	}
	var connection ConnectionView
	if err = json.Unmarshal(registered.Resource, &connection); err != nil {
		t.Fatal(err)
	}
	if connection.Protocol != "local" || connection.Local == nil || !connection.Local.ReadOnly || bytes.Contains(registered.Resource, []byte(directory)) || bytes.Contains(registered.Resource, []byte(configuration)) {
		t.Fatal("local source lost read-only role or exposed host references")
	}
	source := collectionTestSource()
	source.Kind = "local.collect"
	source.Connection = Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}
	d := Definition{Schema: 1, Name: "Approved private local collection", Steps: []Step{}, Source: &source}
	preview, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: d})
	if err != nil || preview.ExternalContact || preview.Collection == nil || preview.Collection.Connection.Protocol != "local" {
		t.Fatal("ordinary local metadata review", err)
	}
	w := f.approved(t, d)
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	authority := tx.AuthorityRevision
	tx.Tx.Rollback(f.ctx)
	body := []byte("independent private producer bytes\n")
	manifest, _, err := digest(&CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}}})
	if err != nil {
		t.Fatal(err)
	}
	writeLocalCollectionFixture(t, filepath.Join(directory, "one.csv"), body)
	writeLocalCollectionFixture(t, filepath.Join(directory, source.Manifest), manifest)
	return localCollectionSetup{f: f, directory: directory, configuration: configuration, connection: connection, source: source, selection: CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: authority}, body: body, manifest: manifest}
}

func localCollectionCounts(t *testing.T, f *fixture) [5]int {
	t.Helper()
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var counts [5]int
	if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM events),(SELECT count(*) FROM workflow_receipts)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4]); err != nil {
		t.Fatal(err)
	}
	return counts
}

func TestLocalCollectionCapturesExactCustodyWithoutProducerMutationOrSendAuthority(t *testing.T) {
	x := newLocalCollection(t)
	job, first := startCollection(t, x.f, x.selection, "local-source-admit")
	before := localCollectionCounts(t, x.f)
	worked, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "local-source-work", CollectionWorkRequest{Hash: job.Hash})
	if err != nil {
		t.Fatal("actual local collector", err)
	}
	v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
	if err != nil || !v.Current || !v.Job.Captured || v.Job.State != "captured" || v.Job.Attempts != 1 || v.Job.Fence != 1 || len(v.Inputs) != 1 || v.BusinessAcceptance != "unknown" {
		t.Fatal("local capture receipt differs", err)
	}
	i := v.Inputs[0]
	file, stream, err := x.f.s.Custody.DownloadPath(x.f.ctx, x.f.scope, i.Target)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(io.LimitReader(stream, int64(len(x.body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(actual, x.body) || file.ID != i.ObjectID || i.FileID == nil || *i.FileID != file.ID || file.Size != int64(len(x.body)) || file.SHA256 != secure.Digest(x.body) {
		t.Fatal("independent exact custody readback differs", err)
	}
	after := localCollectionCounts(t, x.f)
	if after[0] != before[0]+1 || after[1] != before[1] || after[2] != before[2] {
		t.Fatal("read-only capture created send authority or wrong file cardinality", before, after)
	}
	for leaf, want := range map[string][]byte{"one.csv": x.body, x.source.Manifest: x.manifest} {
		got, err := os.ReadFile(filepath.Join(x.directory, leaf))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("producer changed", err)
		}
	}
	if entries, err := os.ReadDir(x.directory); err != nil || len(entries) != 2 {
		t.Fatal("collector wrote producer state", err)
	}
	// Remove the private profile after capture: saved receipts must not reopen it.
	if err = os.Remove(x.configuration); err != nil {
		t.Fatal(err)
	}
	again, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "local-source-work", CollectionWorkRequest{Hash: job.Hash})
	if err != nil || !again.Replayed || !bytes.Equal(again.Resource, worked.Resource) {
		t.Fatal("worker replay reread source or changed receipt", err)
	}
	preview, err := x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection)
	if err != nil {
		t.Fatal(err)
	}
	again, err = x.f.s.StartCollection(x.f.ctx, x.f.scope, "local-source-admit", CollectionStartRequest{Selection: x.selection, Hash: preview.Hash})
	if err != nil || !again.Replayed || !bytes.Equal(again.Resource, first.Resource) || localCollectionCounts(t, x.f) != after {
		t.Fatal("saved admission repeated effects", err)
	}
	if _, err = x.f.s.Run(x.f.ctx, x.f.scope, "local-source-injected-input", RunRequest{Workflow: x.selection.Workflow, FileID: x.f.file.ID}); !errors.Is(err, ErrInput) {
		t.Fatal("manual file bypassed local source lineage", err)
	}
}

func TestLocalCollectionChangedProfileOrRootCannotCaptureAnyFile(t *testing.T) {
	for _, mode := range []string{"configuration", "root"} {
		t.Run(mode, func(t *testing.T) {
			x := newLocalCollection(t)
			job, _ := startCollection(t, x.f, x.selection, "changed-local-source")
			before := localCollectionCounts(t, x.f)
			if mode == "configuration" {
				if err := os.WriteFile(x.configuration, []byte("changed private configuration"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(x.directory, x.directory+"-retained"); err != nil {
					t.Fatal(err)
				}
				if err := protectedfs.EnsureDirectory(x.directory); err != nil {
					t.Fatal(err)
				}
				writeLocalCollectionFixture(t, filepath.Join(x.directory, "one.csv"), x.body)
				writeLocalCollectionFixture(t, filepath.Join(x.directory, x.source.Manifest), x.manifest)
			}
			if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "changed-local-work", CollectionWorkRequest{Hash: job.Hash}); err != nil {
				t.Fatal(err)
			}
			v, err := x.f.s.CollectionStatus(x.f.ctx, x.f.scope, job.ID)
			if err != nil || v.Job.Captured || v.Job.State != "retry" || len(v.Inputs) != 0 || v.Job.Manifest != nil {
				t.Fatal("changed local source captured bytes", err)
			}
			after := localCollectionCounts(t, x.f)
			if after[0] != before[0] || after[1] != before[1] || after[2] != before[2] {
				t.Fatal("changed root/profile created custody or effects", before, after)
			}
		})
	}
}

func TestLocalCollectionRevocationAndSourceOnlyConnectionRemainEnforced(t *testing.T) {
	x := newLocalCollection(t)
	d := Definition{Schema: 1, Name: "Must not send through a local source", Steps: []Step{{ID: "send", Kind: "sftp.deliver", Connection: x.source.Connection, Filename: "one.csv"}}}
	if _, err := x.f.s.Validate(x.f.ctx, x.f.scope, PreviewRequest{Definition: d, FileID: x.f.file.ID}); !errors.Is(err, ErrInput) {
		t.Fatal("read-only connection became a delivery endpoint", err)
	}
	job, _ := startCollection(t, x.f, x.selection, "revoked-local-source")
	if _, err := x.f.s.RevokeConnection(x.f.ctx, x.f.scope, x.connection.ID, x.connection.Version, "revoke-exact-local", Decision{Hash: x.connection.Hash, Revision: x.connection.Revision}); err != nil {
		t.Fatal(err)
	}
	before := localCollectionCounts(t, x.f)
	if _, err := x.f.s.WorkCollection(x.f.ctx, x.f.scope, job.ID, "revoked-local-worker", CollectionWorkRequest{Hash: job.Hash}); !errors.Is(err, store.ErrCollection) {
		t.Fatal("revoked local source ran", err)
	}
	if localCollectionCounts(t, x.f) != before {
		t.Fatal("revoked local source changed durable state")
	}
}

func TestLocalCollectionRuntimeSQLRequiresExactRootAndReadOnlyMeaning(t *testing.T) {
	x := newLocalCollection(t)
	preview, err := x.f.s.PreviewCollection(x.f.ctx, x.f.scope, x.selection)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := startCollection(t, x.f, x.selection, "local-sql-control")
	if _, err = x.f.s.CancelCollection(x.f.ctx, x.f.scope, base.ID, "close-local-sql-slot", Decision{Hash: base.Hash, Revision: base.Revision}); err != nil {
		t.Fatal(err)
	}
	tx, err := x.f.s.Custody.DB.Begin(x.f.ctx, x.f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(x.f.ctx)
	for index, mutate := range []func(map[string]any){nil,
		func(d map[string]any) { d["source"].(map[string]any)["kind"] = "sftp.collect" },
		func(d map[string]any) { d["source_identity"] = strings.Repeat("a", 64) },
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["local"].(map[string]any)["read_only"] = false
		},
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["local"].(map[string]any)["root_fingerprint"] = strings.Repeat("b", 64)
		},
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["local"].(map[string]any)["configuration_sha256"] = strings.Repeat("c", 64)
		},
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["local"].(map[string]any)["root_reference_sha256"] = strings.Repeat("d", 64)
		},
		func(d map[string]any) {
			d["source_connection"].(map[string]any)["local"].(map[string]any)["execute"] = true
		},
	} {
		raw, _ := json.Marshal(preview.Definition)
		var value map[string]any
		if err = json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(value)
		}
		raw, _ = json.Marshal(value)
		var current bool
		if err = tx.Tx.QueryRow(x.f.ctx, `SELECT freightctl_collection_definition_current($1,$2,$3,$4)`, x.f.scope.Tenant, x.f.scope.Partner, tx.Actor, raw).Scan(&current); err != nil || current != (index == 0) {
			t.Fatal("SQL accepted detached local meaning or rejected exact metadata", index, err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "SAVEPOINT local_collection_forgery"); err != nil {
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
		err = tx.SaveCollection(x.f.ctx, &forged, 0)
		if index == 0 {
			if err != nil {
				t.Fatal("matching-event exact local SQL control failed", err)
			}
		} else {
			collectionSQLRefusal(t, err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "ROLLBACK TO SAVEPOINT local_collection_forgery"); err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Tx.Exec(x.f.ctx, "RELEASE SAVEPOINT local_collection_forgery"); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := x.f.s.Connection(x.f.ctx, x.f.scope, x.connection.ID, x.connection.Version)
	if err != nil || !reflect.DeepEqual(stored, &x.connection) {
		t.Fatal("SQL negatives changed the original registered source", err)
	}
}
