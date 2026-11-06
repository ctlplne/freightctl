//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestCollectionUnfinishedBatchCannotExposeItsFirstAcceptedFile(t *testing.T) {
	f, _, x := collectionFixture(t)
	j, _ := startCollection(t, f, x, "unfinished-batch")
	owner := secure.NewID()
	j, _, _, e := f.s.claimCollection(f.ctx, f.scope, j.ID, j.Hash, owner)
	if e != nil {
		t.Fatal(e)
	}
	m := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{{Name: "one.csv", Size: 3, SHA256: secure.Digest([]byte("abc"))}, {Name: "two.csv", Size: 3, SHA256: secure.Digest([]byte("def"))}}}
	_, hash, _ := digest(m)
	if e = f.s.captureCollectionManifest(f.ctx, f.scope, j.ID, owner, j.Fence, m, hash); e != nil {
		t.Fatal(e)
	}
	v, e := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if e != nil {
		t.Fatal(e)
	}
	first := v.Inputs[0]
	_, _, e = f.s.Custody.Disk.StageGenerated(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, first.ObjectID), 3, func(w io.Writer) error { _, e := w.Write([]byte("abc")); return e })
	if e != nil {
		t.Fatal(e)
	}
	if e = f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &first); e != nil {
		t.Fatal(e)
	}
	if _, err := f.s.InspectCollectedExchangeSource(f.ctx, f.scope, j.ID, first.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("unfinished siblings exposed an exchange source", err)
	}
	_, data, e := f.s.Custody.Download(f.ctx, f.scope, first.ObjectID)
	if data != nil {
		data.Close()
	}
	if !errors.Is(e, store.ErrState) {
		t.Fatalf("unfinished batch exposed accepted input before all sibling bytes were verified: %v", e)
	}
	other, _ := approvalPeer(t, f, "Other file administrator", append([]string{}, store.DefaultPermissions...))
	_, otherData, e := f.s.Custody.Download(f.ctx, other, first.ObjectID)
	if otherData != nil {
		otherData.Close()
	}
	if !errors.Is(e, store.ErrState) {
		t.Fatalf("another administrator bypassed the unfinished-batch hold through actor-private input RLS: %v", e)
	}
	for _, identity := range []store.Scope{f.scope, other} {
		tx, err := f.s.Custody.DB.Begin(f.ctx, identity)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Tx.Exec(f.ctx, `UPDATE workflow_collection_file_gates SET captured=true WHERE file_id=$1`, first.ObjectID)
		tx.Tx.Rollback(f.ctx)
		collectionSQLRefusal(t, err)
	}
	if _, e = f.s.Custody.StatPath(f.ctx, f.scope, first.Target); !errors.Is(e, store.ErrNotFound) {
		t.Fatal("unfinished batch path was published", e)
	}
	second := v.Inputs[1]
	_, _, e = f.s.Custody.Disk.StageGenerated(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, second.ObjectID), 3, func(w io.Writer) error { _, e := w.Write([]byte("def")); return e })
	if e != nil {
		t.Fatal(e)
	}
	if e = f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &second); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.completeCollectionWork(f.ctx, f.scope, j.ID, owner, j.Fence, "complete-fixture", secure.Digest([]byte("complete-fixture"))); e != nil {
		t.Fatal(e)
	}
	for _, input := range []store.CollectionInput{first, second} {
		file, body, e := f.s.Custody.DownloadPath(f.ctx, f.scope, input.Target)
		if e != nil {
			t.Fatal("completed exact batch did not publish", e)
		}
		body.Close()
		if file.ID != input.ObjectID {
			t.Fatal("publication changed immutable revision")
		}
	}
	completed, e := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if e != nil || !completed.Job.Captured {
		t.Fatal(completed, e)
	}
	snapshot := func() [4]int {
		t.Helper()
		tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var counts [4]int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_receipts),(SELECT count(*) FROM events)`).Scan(&counts[0], &counts[1], &counts[2], &counts[3]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	before := snapshot()
	source, err := f.s.InspectCollectedExchangeSource(f.ctx, f.scope, j.ID, completed.Inputs[0].ID)
	if err != nil || source.Artifact.ID != *completed.Inputs[0].FileID || source.Artifact.Size != 3 || source.Artifact.SHA256 != secure.Digest([]byte("abc")) || source.StorageVerification != "not-checked" || source.Origin.InputID != completed.Inputs[0].ID {
		t.Fatal("exact completed collection source refused or overstated", err)
	}
	if after := snapshot(); after != before {
		t.Fatal("source review created events/intents/receipts", before, after)
	}
	if _, err = f.s.InspectCollectedExchangeSource(f.ctx, other, j.ID, completed.Inputs[0].ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another administrator adopted actor-private collection source", err)
	}
	if _, e = f.s.CancelCollection(f.ctx, f.scope, j.ID, "cancel-after-capture", Decision{Hash: j.Hash, Revision: completed.Job.Revision}); e != nil {
		t.Fatal(e)
	}
	if _, err = f.s.InspectCollectedExchangeSource(f.ctx, f.scope, j.ID, completed.Inputs[0].ID); err != nil {
		t.Fatal("stopping collection recalled independently authorized captured source", err)
	}
	_, body, e := f.s.Custody.DownloadPath(f.ctx, f.scope, first.Target)
	if e != nil {
		t.Fatal("cancellation claimed to recall already captured local bytes", e)
	}
	body.Close()
}

func collectionFixture(t *testing.T) (*fixture, Reference, CollectionSelection) {
	t.Helper()
	f := setup(t)
	d := f.definition()
	source := collectionTestSource()
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	source.Directory = "/"
	d.Source = &source
	c := f.approved(t, d)
	ref := Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}
	tx, e := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if e != nil {
		t.Fatal(e)
	}
	authority := tx.AuthorityRevision
	tx.Tx.Rollback(f.ctx)
	return f, ref, CollectionSelection{Workflow: ref, Timeout: 120, Authority: authority}
}
func startCollection(t *testing.T, f *fixture, x CollectionSelection, key string) (*store.CollectionJob, *Result) {
	t.Helper()
	p, e := f.s.PreviewCollection(f.ctx, f.scope, x)
	if e != nil {
		t.Fatal(e)
	}
	if p.ExternalContact || !p.ApprovalRequired {
		t.Fatal("preview executed input")
	}
	r, e := f.s.StartCollection(f.ctx, f.scope, key, CollectionStartRequest{Selection: x, Hash: p.Hash})
	if e != nil {
		t.Fatal(e)
	}
	var action CollectionAction
	if json.Unmarshal(r.Resource, &action) != nil {
		t.Fatal("action receipt")
	}
	v, e := f.s.CollectionStatus(f.ctx, f.scope, action.ID)
	if e != nil {
		t.Fatal(e)
	}
	return v.Job, r
}
func TestCollectionJobRequiresApprovedSourceAndKeepsOriginalReceipts(t *testing.T) {
	f, _, x := collectionFixture(t)
	p, e := f.s.PreviewCollection(f.ctx, f.scope, x)
	if e != nil {
		t.Fatal(e)
	}
	request := CollectionStartRequest{Selection: x, Hash: p.Hash}
	j, first := startCollection(t, f, x, "collection-start")
	for _, timestamp := range []time.Time{j.Next, j.Created, j.Deadline} {
		if timestamp.Location() != time.UTC {
			t.Fatal("job timestamp does not honor the UTC wire contract", timestamp)
		}
	}
	if j.State != "queued" || j.Revision != 1 || j.Attempts != 0 || j.Fence != 0 || j.Manifest != nil || j.Owner != "" {
		t.Fatal("queue started a source read", j)
	}
	replayed, e := f.s.StartCollection(f.ctx, f.scope, "collection-start", request)
	if e != nil || !replayed.Replayed || string(replayed.Resource) != string(first.Resource) {
		t.Fatal("original receipt changed", e)
	}
	if _, e = f.s.StartCollection(f.ctx, f.scope, "another-open-job", request); !errors.Is(e, store.ErrCollection) {
		t.Fatal("concurrent family admitted", e)
	}
	cancel, e := f.s.CancelCollection(f.ctx, f.scope, j.ID, "cancel-source", Decision{Hash: j.Hash, Revision: j.Revision})
	if e != nil {
		t.Fatal(e)
	}
	var action CollectionAction
	json.Unmarshal(cancel.Resource, &action)
	if action.State != "cancelled" {
		t.Fatal(action)
	}
	replayed, e = f.s.StartCollection(f.ctx, f.scope, "collection-start", request)
	if e != nil || !replayed.Replayed || string(replayed.Resource) != string(first.Resource) {
		t.Fatal("cancel rewrote queued receipt", e)
	}
	page, e := f.s.Collections(f.ctx, f.scope, "", 1)
	if e != nil || len(page.Jobs) != 1 || page.Jobs[0].ID != j.ID {
		t.Fatal(page, e)
	}
}
func TestCollectionSourceRevocationIsVisibleAndManualFileInjectionRefused(t *testing.T) {
	f, ref, x := collectionFixture(t)
	j, _ := startCollection(t, f, x, "source-to-revoke")
	if _, e := f.s.Run(f.ctx, f.scope, "manual-source-injection", RunRequest{Workflow: ref, FileID: f.file.ID}); !errors.Is(e, ErrInput) {
		t.Fatal("manual file bypassed collection lineage", e)
	}
	if _, e := f.s.RevokeConnection(f.ctx, f.scope, f.connection.ID, f.connection.Version, "revoke-collection-source", Decision{Hash: f.connection.Hash, Revision: f.connection.Revision}); e != nil {
		t.Fatal(e)
	}
	v, e := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if e != nil || v.Current || v.Observed != "attention" {
		t.Fatal("metadata hid revoked source", v, e)
	}
	if _, e = f.s.PreviewCollection(f.ctx, f.scope, x); e == nil {
		t.Fatal("revoked source retained collection authority")
	}
	_, e = f.s.CancelCollection(f.ctx, f.scope, j.ID, secure.NewID(), Decision{Hash: j.Hash, Revision: j.Revision})
	if e != nil {
		t.Fatal("current owner cannot cancel revoked source", e)
	}
}
