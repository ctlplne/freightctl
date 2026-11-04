//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestCollectedFTPSBytesNeedExactOrdinaryIntakeCheckAndRelease(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			checker, policy, _ := policyAndFile(t, f, goodCSV, false)
			producer, transport, listener := intakeFTPSReceiver(t, mode)
			publish := func(name string, data []byte) {
				t.Helper()
				if _, _, err := producer.wf.Custody.AcceptAt(producer.ctx, producer.scope, secure.NewID(), int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/inbox/" + name}); err != nil {
					t.Fatal(err)
				}
			}
			publish("settlement.csv", []byte(goodCSV))
			manifest := workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "settlement.csv", Size: int64(len(goodCSV)), SHA256: secure.Digest([]byte(goodCSV))}}}
			raw, _ := json.Marshal(manifest)
			publish("settlement.ready.json", raw)
			registered, err := f.wf.RegisterConnection(f.ctx, f.scope, "collected-ftps-source", workflow.ConnectionRequest{Directory: "/inbox", FTPS: &transport})
			var connection workflow.ConnectionView
			if err != nil || json.Unmarshal(registered.Resource, &connection) != nil {
				t.Fatal("exact source connection", err)
			}
			source := workflow.CollectionSource{Kind: "ftps.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "settlement.ready.json", Directory: "/", Contract: workflow.CollectionContract, MaxFiles: 1, MaxFile: 1024, MaxTotal: 1024}
			definition := workflow.Definition{Schema: 1, Name: "Checked FTPS collection", Steps: []workflow.Step{}, Source: &source}
			saved, err := f.wf.Draft(f.ctx, f.scope, "collected-ftps-workflow", workflow.DraftRequest{Definition: definition})
			var w store.Configuration
			if err != nil || json.Unmarshal(saved.Resource, &w) != nil {
				t.Fatal(err)
			}
			if _, err = f.wf.Decide(f.ctx, f.scope, w.ID, w.Version, "approve-collected-ftps", "approve", workflow.Decision{Hash: w.Hash, Revision: w.Revision}); err != nil {
				t.Fatal(err)
			}
			tx, err := f.wf.Custody.DB.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			authority := tx.AuthorityRevision
			tx.Tx.Rollback(f.ctx)
			selection := workflow.CollectionSelection{Workflow: workflow.Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Timeout: 120, Authority: authority}
			preview, err := f.wf.PreviewCollection(f.ctx, f.scope, selection)
			if err != nil || preview.ExternalContact || listener.contacts.Load() != 0 {
				t.Fatal("intake preview contacted source", err)
			}
			started, err := f.wf.StartCollection(f.ctx, f.scope, "checked-ftps-start", workflow.CollectionStartRequest{Selection: selection, Hash: preview.Hash})
			var action workflow.CollectionAction
			if err != nil || json.Unmarshal(started.Resource, &action) != nil {
				t.Fatal(err)
			}
			if _, err = f.wf.WorkCollection(f.ctx, f.scope, action.ID, "checked-ftps-worker", workflow.CollectionWorkRequest{Hash: action.Hash}); err != nil {
				t.Fatal(err)
			}
			v, err := f.wf.CollectionStatus(f.ctx, f.scope, action.ID)
			if err != nil || !v.Job.Captured || len(v.Inputs) != 1 || v.Inputs[0].FileID == nil {
				t.Fatal("checked source was not durably copied", err)
			}
			input := v.Inputs[0]
			fileID := *input.FileID
			requireHeld := func() {
				t.Helper()
				file, stream, err := f.wf.Custody.Download(f.ctx, f.scope, fileID)
				if stream != nil {
					stream.Close()
				}
				if !errors.Is(err, store.ErrState) {
					t.Fatal("FTPS acquisition bypassed the ordinary intake hold", file, err)
				}
				if _, err = f.wf.Custody.StatPath(f.ctx, f.scope, input.Target); !errors.Is(err, store.ErrNotFound) {
					t.Fatal("held collected bytes were published", err)
				}
			}
			requireHeld()
			if _, err = checker.Run(f.ctx, f.scope, fileID, "check-collected-ftps"); err != nil {
				t.Fatal(err)
			}
			checked := getCheck(t, checker, f, fileID)
			if checked.State != "passed" || checked.Attempts != 1 || checked.PolicyHash != policy.Hash {
				t.Fatal("collected revision was checked under a different policy")
			}
			requireHeld()
			wrong := releaseDecision(checked)
			wrong.ReportHash = strings.Repeat("f", 64)
			if _, err = checker.Release(f.ctx, f.scope, fileID, "wrong-collected-report", wrong); !errors.Is(err, store.ErrRevision) {
				t.Fatal("wrong report released collected bytes", err)
			}
			requireHeld()
			if _, err = checker.Release(f.ctx, f.scope, fileID, "release-collected-ftps", releaseDecision(checked)); err != nil {
				t.Fatal(err)
			}
			contacts := listener.contacts.Load()
			if _, err = f.wf.RefreshCollection(f.ctx, f.scope, action.ID, "publish-released-collected-ftps", workflow.Decision{Hash: v.Job.Hash, Revision: v.Job.Revision}); err != nil {
				t.Fatal(err)
			}
			file, stream, err := f.wf.Custody.DownloadPath(f.ctx, f.scope, input.Target)
			if err != nil {
				t.Fatal("released collected path unavailable", err)
			}
			data, err := io.ReadAll(io.LimitReader(stream, int64(len(goodCSV))+1))
			stream.Close()
			if err != nil || !bytes.Equal(data, []byte(goodCSV)) || file.ID != fileID || file.SHA256 != secure.Digest(data) || file.Policy != "intake-csv-v1:"+policy.Hash || listener.contacts.Load() != contacts {
				t.Fatal("release changed immutable copy or reread source", err)
			}
		})
	}
}
