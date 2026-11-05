//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestReviewedOnwardPreparesNoEffectsAndKeepsOriginalRunAfterRevocation(t *testing.T) {
	f := setup(t)
	definition := f.definition()
	configuration := f.approved(t, definition)
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile, Workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: store.ExchangeArtifact{ID: f.file.ID, Size: f.file.Size, SHA256: f.file.SHA256, Policy: f.file.Policy}}
	counts := func() (int, int, int, int) {
		t.Helper()
		tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var runs, intents, receipts, events int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_receipts),(SELECT count(*) FROM events)`).Scan(&runs, &intents, &receipts, &events); err != nil {
			t.Fatal(err)
		}
		return runs, intents, receipts, events
	}
	r0, i0, c0, e0 := counts()
	review, err := f.s.PrepareOnward(f.ctx, f.scope, request)
	if err != nil || review.State != "review-only" || review.ExternalContact || len(review.Effects) != 2 || review.ReceiverPersistence != "unknown" || review.BusinessProcessing != "unknown" {
		t.Fatal("review changed effects or receipt meaning", err)
	}
	r1, i1, c1, e1 := counts()
	if r0 != r1 || i0 != i1 || c0 != c1 || e0 != e1 {
		t.Fatal("preparation created durable effects")
	}
	stale := OnwardStart{Request: request, ReviewHash: request.Artifact.SHA256}
	if _, err = f.s.StartOnward(f.ctx, f.scope, "stale-onward-review", stale); !errors.Is(err, store.ErrRevision) {
		t.Fatal("unreviewed binding staged intents", err)
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	first, err := f.s.StartOnward(f.ctx, f.scope, "exact-onward-run", start)
	if err != nil || first.Replayed {
		t.Fatal("reviewed ordinary staging failed", err)
	}
	var original store.WorkflowRun
	if json.Unmarshal(first.Resource, &original) != nil {
		t.Fatal("ordinary run receipt malformed")
	}
	r1, i1, c1, _ = counts()
	if r1 != r0+1 || i1 != i0+2 || c1 != c0+1 {
		t.Fatal("run and intents/receipt did not commit together")
	}
	if _, err = f.s.Decide(f.ctx, f.scope, configuration.ID, configuration.Version, "onward-workflow-revoke", "revoke", Decision{Hash: configuration.Hash, Revision: configuration.Revision}); err != nil {
		t.Fatal(err)
	}
	// Original acceptance survives later configuration changes, without
	// creating another run, waking a worker, or promising a remote effect.

	originalMaximum := f.s.Custody.MaxFile
	f.s.Custody.MaxFile = 2 // New-run admission cannot erase the accepted3byte receipt.
	replayed, err := f.s.StartOnward(f.ctx, f.scope, "exact-onward-run", start)
	if err != nil || !replayed.Replayed || string(replayed.Resource) != string(first.Resource) {
		t.Fatal("historical retry changed original accepted run", err)
	}
	if _, err = f.s.StartOnward(f.ctx, f.scope, "new-after-revocation", start); err == nil {
		t.Fatal("historical receipt reactivated revoked work")
	}
	lookedUp, err := f.s.OnwardReceipt(f.ctx, f.scope, OnwardLookup{Start: start, ReceiptKey: "exact-onward-run"})
	if err != nil || string(lookedUp.Resource) != string(first.Resource) {
		t.Fatal("receipt lookup lost exact original meaning", err)
	}
	if _, err = f.s.OnwardReceipt(f.ctx, f.scope, OnwardLookup{Start: start, ReceiptKey: "not-started"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("lookup created or adopted a missing run", err)
	}
	f.s.Custody.MaxFile = originalMaximum
	changed := start
	changed.Request.Artifact.Size++
	if _, err = f.s.StartOnward(f.ctx, f.scope, "exact-onward-run", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("same key changed onward meaning", err)
	}
	r2, i2, c2, _ := counts()
	if r2 != r1 || i2 != i1 || c2 != c1+1 { // Only workflow revocation adds a workflow receipt.
		t.Fatal("recovery changed durable run/intent/command counts")
	}
	if _, err = f.s.Work(f.ctx, f.scope, original.ID, "cannot-awaken-revoked-onward"); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked onward work did not refuse at its ordinary state guard", err)
	}
}

func TestReviewedOnwardReceiptCannotAdoptLegacyRunOrOtherPrincipal(t *testing.T) {
	f := setup(t)
	configuration := f.approved(t, f.definition())
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile, Workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: store.ExchangeArtifact{ID: f.file.ID, Size: f.file.Size, SHA256: f.file.SHA256, Policy: f.file.Policy}}
	review, err := f.s.PrepareOnward(f.ctx, f.scope, request)
	if err != nil {
		t.Fatal(err)
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	if _, err = f.s.Run(f.ctx, f.scope, "ordinary-non-onward", RunRequest{Workflow: request.Workflow, FileID: request.Artifact.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.OnwardReceipt(f.ctx, f.scope, OnwardLookup{Start: start, ReceiptKey: "ordinary-non-onward"}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("legacy run adopted reviewed-onward authority", err)
	}
	if _, err = f.s.StartOnward(f.ctx, f.scope, "actual-reviewed-onward", start); err != nil {
		t.Fatal(err)
	}
	other, _ := approvalPeer(t, f, "Other participant", append([]string{}, store.DefaultPermissions...))
	if _, err = f.s.OnwardReceipt(f.ctx, other, OnwardLookup{Start: start, ReceiptKey: "actual-reviewed-onward"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other principal learned private onward receipt", err)
	}
	if _, err = f.s.PrepareOnward(f.ctx, other, request); err == nil {
		t.Fatal("unrelated participant adopted workflow/source authority")
	}
}

func TestReviewedOnwardReceiptCannotBeAdoptedAfterCredentialRotation(t *testing.T) {
	f := setup(t)
	configuration := f.approved(t, f.definition())
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile, Workflow: Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Artifact: store.ExchangeArtifact{ID: f.file.ID, Size: f.file.Size, SHA256: f.file.SHA256, Policy: f.file.Policy}}
	review, err := f.s.PrepareOnward(f.ctx, f.scope, request)
	if err != nil {
		t.Fatal(err)
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	if _, err = f.s.StartOnward(f.ctx, f.scope, "pre-rotation-onward", start); err != nil {
		t.Fatal(err)
	}
	identity, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	account, err := f.s.Custody.DB.Account(f.ctx, f.scope, identity.Actor)
	if err != nil {
		t.Fatal(err)
	}
	replacement := secure.Digest([]byte("synthetic rotated onward credential"))
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-onward-credential", store.AccountCommand{Operation: "rotate", ID: account.ID, ExpectedRevision: account.Revision, CredentialHash: replacement}); err != nil {
		t.Fatal(err)
	}
	next := f.scope
	next.TokenHash = replacement
	if _, err = f.s.OnwardReceipt(f.ctx, next, OnwardLookup{Start: start, ReceiptKey: "pre-rotation-onward"}); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("rotated authority adopted an old private onward receipt", err)
	}
}
