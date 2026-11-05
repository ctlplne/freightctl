//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"io"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// Actual native FTPS/custody peer, not an independent stock receiver claim.
func TestReviewedOnwardKeepsIntakeHoldsAndOriginalReceiptAfterPolicyChange(t *testing.T) {
	f := setup(t)
	receiver, ftp, listener := intakeFTPSReceiver(t, "explicit")
	checking, policy, file := policyAndFile(t, f, goodCSV, true)
	registered, err := f.wf.RegisterConnection(f.ctx, f.scope, "onward-ftps-connection", workflow.ConnectionRequest{Directory: "/inbox", FTPS: &ftp})
	if err != nil {
		t.Fatal(err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil {
		t.Fatal("connection response")
	}
	definition := workflow.Definition{Schema: 1, Name: "Reviewed artifact onward", Steps: []workflow.Step{{ID: "send", Kind: "ftps.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "onward.csv"}}}
	drafted, err := f.wf.Draft(f.ctx, f.scope, "onward-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var configuration store.Configuration
	if json.Unmarshal(drafted.Resource, &configuration) != nil {
		t.Fatal("draft response")
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, configuration.ID, configuration.Version, "onward-approve", "approve", workflow.Decision{Hash: configuration.Hash, Revision: configuration.Revision}); err != nil {
		t.Fatal(err)
	}
	request := workflow.OnwardRequest{Schema: 1, Profile: workflow.OnwardProfile, Workflow: workflow.Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}}
	if _, err = f.wf.PrepareOnward(f.ctx, f.scope, request); !errors.Is(err, store.ErrState) {
		t.Fatal("onward preparation bypassed held bytes", err)
	}
	if listener.contacts.Load() != 0 {
		t.Fatal("held review contacted a receiver")
	}
	if _, err = checking.Run(f.ctx, f.scope, file.ID, "onward-check"); err != nil {
		t.Fatal(err)
	}
	check := getCheck(t, checking, f, file.ID)
	if _, err = checking.Release(f.ctx, f.scope, file.ID, "onward-release", releaseDecision(check)); err != nil {
		t.Fatal(err)
	}
	review, err := f.wf.PrepareOnward(f.ctx, f.scope, request)
	if err != nil || review.ExternalContact {
		t.Fatal("released source did not prepare without contact", err)
	}
	start := workflow.OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	accepted, err := f.wf.StartOnward(f.ctx, f.scope, "onward-start", start)
	if err != nil || listener.contacts.Load() != 0 {
		t.Fatal("staging contacted receiver or failed", err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(accepted.Resource, &run) != nil {
		t.Fatal("run response")
	}
	work, err := f.wf.Work(f.ctx, f.scope, run.ID, "onward-one-step")
	if err != nil || work.Status.ObservedState != "succeeded" || listener.contacts.Load() == 0 {
		t.Fatal("actual FTPS work did not produce ordinary evidence", err)
	}
	actual, body, err := receiver.wf.Custody.DownloadPath(receiver.ctx, receiver.scope, "/inbox/onward.csv")
	if err != nil {
		t.Fatal("actual receiver lacks new onward bytes", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(body, int64(len(goodCSV))+1))
	body.Close()
	if readErr != nil || string(data) != goodCSV || actual.Size != int64(len(goodCSV)) || actual.SHA256 != secure.Digest([]byte(goodCSV)) {
		t.Fatal("receiver bytes differ from reviewed source")
	}
	contacts := listener.contacts.Load()
	next := testPolicy(t)
	next.Columns[0].Name = "changed"
	if _, err = checking.Register(f.ctx, f.scope, "onward-new-policy", PolicyRequest{ExpectedVersion: policy.Version, Definition: next}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.wf.PrepareOnward(f.ctx, f.scope, request); !errors.Is(err, store.ErrState) {
		t.Fatal("new policy did not withhold old source", err)
	}
	replayed, err := f.wf.StartOnward(f.ctx, f.scope, "onward-start", start)
	if err != nil || !replayed.Replayed || string(replayed.Resource) != string(accepted.Resource) {
		t.Fatal("current hold erased historical accepted run", err)
	}
	if _, err = f.wf.StartOnward(f.ctx, f.scope, "new-start-after-hold", start); !errors.Is(err, store.ErrState) {
		t.Fatal("historical review bypassed current hold", err)
	}
	if _, err = f.wf.Work(f.ctx, f.scope, run.ID, "different-key-after-hold"); !errors.Is(err, store.ErrState) {
		t.Fatal("held source did not refuse before transfer", err)
	}
	if listener.contacts.Load() != contacts {
		t.Fatal("held retry contacted receiver again")
	}
}
