//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCollectedHandoffReceiptFailureRollsBackAndConcurrentOriginalKeyCreatesOneSuccessor(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	_, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	before := routingPreviewCounts(t, f)
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_collected_handoff_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'exact collected handoff receipt failure';END $$;CREATE TRIGGER freightctl_collected_handoff_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_collected_handoff_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-failed-receipt", "execute", Decision{Hash: h.Hash, Revision: h.Revision})
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "P0001" || pgerr.Message != "exact collected handoff receipt failure" {
		t.Fatal("exact receipt failure not observed", err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("receipt failure retained cancellation, successor or events", before, after)
	}
	old, err := f.s.Status(f.ctx, f.scope, x.SourceRun)
	if err != nil || old.Run.State != "queued" || old.Steps[0].State != "queued" || old.Steps[0].Attempts != 0 {
		t.Fatal("source cancellation survived rollback", err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_collected_handoff_receipt_failure ON workflow_receipts`); err != nil {
		t.Fatal(err)
	}
	type response struct {
		result *Result
		err    error
	}
	ready := make(chan struct{})
	out := make(chan response, 2)
	for n := 0; n < 2; n++ {
		go func() {
			<-ready
			r, e := f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-concurrent-original-key", "execute", Decision{Hash: h.Hash, Revision: h.Revision})
			out <- response{r, e}
		}()
	}
	close(ready)
	replays := 0
	for n := 0; n < 2; n++ {
		r := <-out
		done := handoffRecord(t, r.result, r.err)
		if done.State != "completed" || done.PlannedRunID != h.PlannedRunID {
			t.Fatal("concurrent successor identity changed")
		}
		if r.result.Replayed {
			replays++
		}
	}
	if replays != 1 {
		t.Fatal("concurrent original key did not recover exactly one receipt", replays)
	}
	if after := routingPreviewCounts(t, f); after[0] != before[0]+1 || after[1] != before[1]+1 {
		t.Fatal("concurrent retry duplicated work", before, after)
	}
	var sourceTx, targetTx, handoffTx string
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT xmin::text FROM workflow_runs WHERE run_id=$1),(SELECT xmin::text FROM workflow_runs WHERE run_id=$2),(SELECT xmin::text FROM workflow_collection_handoffs WHERE id=$3)`, x.SourceRun, h.PlannedRunID, h.ID).Scan(&sourceTx, &targetTx, &handoffTx); err != nil || sourceTx != targetTx || sourceTx != handoffTx {
		t.Fatal("handoff did not commit atomically", err)
	}
}

func TestCollectedHandoffApprovalCannotCancelAnIntentClaimedByAWorker(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	_, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	status, err := f.s.Status(f.ctx, f.scope, x.SourceRun)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, status.Steps[0].DeliveryID, secure.NewID()); err != nil {
		t.Fatal(err)
	}
	before := routingPreviewCounts(t, f)
	if _, err = f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-claimed-refusal", "execute", Decision{Hash: h.Hash, Revision: h.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("claimed work entered untouched profile", err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("stale approval changed claimed work")
	}
	view, err := f.s.CollectionHandoffStatus(f.ctx, f.scope, h.JobID, h.ID)
	if err != nil || view.Current || view.Handoff.State != "approved" {
		t.Fatal("claimed work revived old consent", err)
	}
	h = decideCollectionHandoff(t, f, h, "cancel", "withdraw-claimed-proposal")
	if h.State != "cancelled" {
		t.Fatal("stale proposal cannot be withdrawn")
	}
}

func TestCollectedHandoffRevokedTargetCannotExecuteButHistoricalReceiptRemainsReadable(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	_, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	receipt, err := f.s.CollectionHandoffReceipt(f.ctx, f.scope, h.JobID, "handoff-approve")
	if err != nil || !receipt.Replayed {
		t.Fatal(err)
	}
	if _, err = f.s.Decide(f.ctx, f.scope, x.Workflow.ID, x.Workflow.Version, "revoke-handoff-target", "revoke", Decision{Hash: x.Workflow.Hash, Revision: 2}); err != nil {
		t.Fatal(err)
	}
	before := routingPreviewCounts(t, f)
	if _, err = f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-revoked-target", "execute", Decision{Hash: h.Hash, Revision: h.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked target executed", err)
	}
	again, err := f.s.CollectionHandoffReceipt(f.ctx, f.scope, h.JobID, "handoff-approve")
	if err != nil || !bytes.Equal(receipt.Resource, again.Resource) {
		t.Fatal("historical receipt was lost", err)
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("refusal/history read wrote effects")
	}
	h = decideCollectionHandoff(t, f, h, "cancel", "cancel-revoked-target")
	if h.State != "cancelled" {
		t.Fatal("cannot cancel stale target proposal")
	}
}

func TestCollectedHandoffCanReplaceRevokedRoutingAndRetainRepeatedSuccessorLineage(t *testing.T) {
	f, captured, x, originalRef := capturedRoutingAuthorizationFixture(t)
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "old-route-propose")
	a = decideRoutingAuthorization(t, f, a, "approve", "old-route-approve")
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "old-route-admit", x.Collection); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
	if err != nil || view.Inputs[0].RunID == nil {
		t.Fatal(err)
	}
	oldRun := *view.Inputs[0].RunID
	a = decideRoutingAuthorization(t, f, a, "revoke", "old-route-revoke")
	status, err := f.s.Status(f.ctx, f.scope, oldRun)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, status.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrCollection) {
		t.Fatal("revoked old routing did not fence delivery", err)
	}
	var raw []byte
	if err = f.admin.QueryRow(f.ctx, `SELECT definition FROM workflow_revisions WHERE workflow_id=$1 AND version=$2`, x.Workflow.ID, x.Workflow.Version).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var d Definition
	if Decode(raw, &d) != nil {
		t.Fatal("target definition")
	}
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}
	r, err := f.s.Draft(f.ctx, f.scope, "handoff-target-v3", DraftRequest{ID: x.Workflow.ID, ExpectedVersion: x.Workflow.Version, Definition: d})
	if err != nil {
		t.Fatal(err)
	}
	var target store.Configuration
	if json.Unmarshal(r.Resource, &target) != nil {
		t.Fatal("target draft")
	}
	r, err = f.s.Decide(f.ctx, f.scope, target.ID, target.Version, "handoff-approve-v3", "approve", Decision{Hash: target.Hash, Revision: target.Revision})
	if err != nil || json.Unmarshal(r.Resource, &target) != nil {
		t.Fatal("target approval", err)
	}
	selection := CollectionHandoffSelection{InputID: view.Inputs[0].ID, SourceRun: oldRun, Workflow: Reference{ID: target.ID, Version: target.Version, Hash: target.Hash}, Authority: 1}
	_, h := proposeCollectionHandoff(t, f, captured.Job.ID, selection)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-v3-approve")
	h = decideCollectionHandoff(t, f, h, "execute", "handoff-v3-execute")
	selection.SourceRun = h.PlannedRunID
	selection.Workflow = originalRef
	p, err := f.s.PreviewCollectionHandoff(f.ctx, f.scope, h.JobID, selection)
	if err != nil {
		t.Fatal("successor could not enter a new governed handoff", err)
	}
	r, err = f.s.ProposeCollectionHandoff(f.ctx, f.scope, h.JobID, "second-handoff-propose", CollectionHandoffProposal{Selection: selection, Hash: p.Hash})
	second := handoffRecord(t, r, err)
	second = decideCollectionHandoff(t, f, second, "approve", "second-handoff-approve")
	second = decideCollectionHandoff(t, f, second, "execute", "second-handoff-execute")
	final, err := f.s.CollectionStatus(f.ctx, f.scope, h.JobID)
	if err != nil || !reflect.DeepEqual(final.Inputs, view.Inputs) || !reflect.DeepEqual(final.Job, view.Job) {
		t.Fatal("repeated handoff rewrote original capture", err)
	}
	last, err := f.s.Status(f.ctx, f.scope, second.PlannedRunID)
	if err != nil || last.Run.WorkflowVersion != originalRef.Version || last.Run.Source.ID != *view.Inputs[0].FileID || last.Steps[0].Attempts != 0 {
		t.Fatal("repeated successor changed source or contacted receiver", err)
	}
	page, err := f.s.CollectionHandoffHistory(f.ctx, f.scope, h.JobID, "", 1)
	if err != nil || len(page.Handoffs) != 1 || page.Next == "" {
		t.Fatal("bounded handoff history missing cursor", err)
	}
	page2, err := f.s.CollectionHandoffHistory(f.ctx, f.scope, h.JobID, page.Next, 1)
	if err != nil || len(page2.Handoffs) != 1 || page2.Next != "" || page.Handoffs[0].ID == page2.Handoffs[0].ID {
		t.Fatal("bounded handoff history repeated or lost link", err)
	}
}

func TestCollectedHandoffPrivateHistoryReceiptsAndAuditRemainScoped(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	_, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	h = decideCollectionHandoff(t, f, h, "execute", "handoff-execute")
	peer, _ := approvalPeer(t, f, "Other collected operator", append([]string{}, store.DefaultPermissions...))
	if _, err := f.s.CollectionHandoffStatus(f.ctx, peer, h.JobID, h.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("peer read private handoff", err)
	}
	if _, err := f.s.CollectionHandoffHistory(f.ctx, peer, h.JobID, "", 20); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("peer listed private handoff", err)
	}
	if _, err := f.s.CollectionHandoffReceipt(f.ctx, peer, h.JobID, "handoff-execute"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("peer recovered private receipt", err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var bypass, owns bool
	err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_collection_handoffs),(SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user),(SELECT pg_get_userbyid(relowner)=current_user FROM pg_class WHERE oid='workflow_collection_handoffs'::regclass)`).Scan(&count, &bypass, &owns)
	tx.Tx.Rollback(f.ctx)
	if err != nil || count != 0 || bypass || owns {
		t.Fatal("handoff RLS requires non-owner runtime without bypass", count, bypass, owns, err)
	}
	rows, err := f.admin.Query(f.ctx, `SELECT event_id::text,payload FROM events WHERE position($1 IN payload::text)>0`, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	originals := map[string][]byte{}
	for rows.Next() {
		var id string
		var payload []byte
		if err = rows.Scan(&id, &payload); err != nil {
			t.Fatal(err)
		}
		originals[id] = append([]byte(nil), payload...)
	}
	rows.Close()
	if rows.Err() != nil || len(originals) < 7 {
		t.Fatal("missing handoff and cancellation journal records", len(originals), rows.Err())
	}
	feed, err := f.s.Custody.DB.Events(f.ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := f.s.Custody.DB.SnapshotEvents(f.ctx, peer, 1000, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range [][]store.Event{feed, audit.Events} {
		seen := 0
		for _, e := range surface {
			if raw, ok := originals[e.ID]; ok {
				seen++
				var envelope struct {
					Redacted bool   `json:"redacted"`
					Hash     string `json:"source_payload_sha256"`
				}
				if json.Unmarshal(e.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(raw) || bytes.Contains(e.Payload, []byte(h.ID)) {
					t.Fatal("private handoff payload escaped exact digest envelope", e.Kind)
				}
			}
		}
		if seen != len(originals) {
			t.Fatal("feed/audit dropped handoff records", seen, len(originals))
		}
	}
	page, err := f.s.CollectionHandoffHistory(f.ctx, f.scope, h.JobID, "", 1)
	if err != nil || len(page.Handoffs) != 1 || page.Handoffs[0].ID != h.ID || page.Next != "" {
		t.Fatal("owner history lost original link", err)
	}
}

func queuedCollectionHandoffFixture(t *testing.T) (*fixture, *CollectionView, CollectionHandoffSelection) {
	t.Helper()
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	// Materialize original revision-1 work first. Its capture assignment must
	// survive the later decision to use the independently approved revision 2.
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "handoff-original-admit", x.Collection); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
	if err != nil || view.Inputs[0].RunID == nil {
		t.Fatal("original assignment", err)
	}
	return f, view, CollectionHandoffSelection{InputID: view.Inputs[0].ID, SourceRun: *view.Inputs[0].RunID, Workflow: x.Workflow, Authority: 1}
}
func handoffRecord(t *testing.T, result *Result, err error) *store.CollectionHandoff {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Kind    string                   `json:"kind"`
		Handoff *store.CollectionHandoff `json:"handoff"`
	}
	if json.Unmarshal(result.Resource, &out) != nil || out.Kind != "workflow_collection_handoff" || out.Handoff == nil {
		t.Fatal("handoff receipt shape")
	}
	return out.Handoff
}
func proposeCollectionHandoff(t *testing.T, f *fixture, job string, x CollectionHandoffSelection) (*CollectionHandoffPreview, *store.CollectionHandoff) {
	t.Helper()
	p, err := f.s.PreviewCollectionHandoff(f.ctx, f.scope, job, x)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.s.ProposeCollectionHandoff(f.ctx, f.scope, job, "handoff-propose", CollectionHandoffProposal{Selection: x, Hash: p.Hash})
	return p, handoffRecord(t, r, err)
}
func decideCollectionHandoff(t *testing.T, f *fixture, h *store.CollectionHandoff, action, key string) *store.CollectionHandoff {
	t.Helper()
	r, err := f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, key, action, Decision{Hash: h.Hash, Revision: h.Revision})
	return handoffRecord(t, r, err)
}

func TestCollectedHandoffPreservesOriginalAssignmentAndAtomicallyQueuesReviewedSuccessor(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	before := routingPreviewCounts(t, f)
	p, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	if h.State != "proposed" || h.PlannedRunID == x.SourceRun || !p.ApprovalRequired || p.ExternalContact {
		t.Fatal("proposal invented execution")
	}
	if _, err := f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-before-approval", "execute", Decision{Hash: h.Hash, Revision: h.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("unapproved handoff executed", err)
	}
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	approved := *h
	h = decideCollectionHandoff(t, f, h, "execute", "handoff-execute")
	if h.State != "completed" {
		t.Fatal("missing completion")
	}
	r, err := f.s.DecideCollectionHandoff(f.ctx, f.scope, h.JobID, h.ID, "handoff-execute", "execute", Decision{Hash: approved.Hash, Revision: approved.Revision})
	replayed := handoffRecord(t, r, err)
	if !r.Replayed || !reflect.DeepEqual(h, replayed) {
		t.Fatal("lost response did not recover original handoff")
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, original.Job.ID)
	if err != nil || !reflect.DeepEqual(view.Job, original.Job) || !reflect.DeepEqual(view.Inputs, original.Inputs) {
		t.Fatal("handoff rewrote original capture or assignment", err)
	}
	old, err := f.s.Status(f.ctx, f.scope, x.SourceRun)
	if err != nil || old.Run.State != "cancelled" || old.Run.Reason != "collection_handoff" {
		t.Fatal("old run not cancelled", err)
	}
	for _, step := range old.Steps {
		if step.State != "cancelled" || step.Attempts != 0 || step.Ciphertext != nil {
			t.Fatal("old external effect was not untouched")
		}
	}
	next, err := f.s.Status(f.ctx, f.scope, h.PlannedRunID)
	if err != nil || next.Run.WorkflowVersion != x.Workflow.Version || next.Run.RoutingID != "" || next.Run.Source != old.Run.Source || next.Run.PlanHash != p.Definition.PlanHash {
		t.Fatal("successor does not match reviewed target", err)
	}
	var oldPlan, newPlan ExecutionPlan
	if Decode(old.Run.Plan, &oldPlan) != nil || Decode(next.Run.Plan, &newPlan) != nil || !reflect.DeepEqual(oldPlan.Facts, newPlan.Facts) || !reflect.DeepEqual(newPlan, p.Definition.Plan) {
		t.Fatal("successor invented captured facts or branch effects")
	}
	if len(next.Steps) != 1 || next.Steps[0].ID != "second" || next.Steps[0].Attempts != 0 {
		t.Fatal("successor effect selection changed")
	}
	if after := routingPreviewCounts(t, f); after[0] != before[0]+1 || after[1] != before[1]+1 {
		t.Fatal("handoff duplicated or contacted receiver", before, after)
	}
	var attempts int
	if err := f.admin.QueryRow(f.ctx, `SELECT coalesce(sum(attempts),0) FROM delivery_intents`).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal("handoff made external attempts", attempts, err)
	}
	if _, err := f.s.PreviewCollectionHandoff(f.ctx, f.scope, h.JobID, x); !errors.Is(err, store.ErrState) {
		t.Fatal("old source received another successor", err)
	}
}

func TestCollectedHandoffSQLRejectsForgedPlanAndUnpairedCancellation(t *testing.T) {
	f, original, x := queuedCollectionHandoffFixture(t)
	p, err := f.s.PreviewCollectionHandoff(f.ctx, f.scope, original.Job.ID, x)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Definition
	d.Plan.Facts.Source.Name = "invented-source.csv"
	raw, hash, err := digest(d)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.collectionBegin(f.ctx, f.scope, "workflow_execute", "workflow_manage", "read", "write", "list")
	if err != nil {
		t.Fatal(err)
	}
	err = tx.SaveCollectionHandoff(f.ctx, &store.CollectionHandoff{ID: secure.NewID(), JobID: original.Job.ID, InputID: x.InputID, SourceRunID: x.SourceRun, PlannedRunID: secure.NewID(), Definition: raw, Hash: hash, State: "proposed", Revision: 1}, 0)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	_, h := proposeCollectionHandoff(t, f, original.Job.ID, x)
	h = decideCollectionHandoff(t, f, h, "approve", "handoff-approve")
	tx, err = f.s.collectionBegin(f.ctx, f.scope, "workflow_execute", "read", "write", "list")
	if err != nil {
		t.Fatal(err)
	}
	intent, err := tx.Delivery(f.ctx, p.Definition.Intents[0].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	prior := intent.Revision
	intent.State = "cancelled"
	intent.Revision++
	intent.Observation, _ = json.Marshal(map[string]string{"code": "collection_handoff", "handoff_id": h.ID})
	if err = tx.SaveDelivery(f.ctx, intent, prior); err == nil {
		err = tx.Tx.Commit(f.ctx)
	} else {
		tx.Tx.Rollback(f.ctx)
	}
	collectionSQLRefusal(t, err)
	view, err := f.s.CollectionHandoffStatus(f.ctx, f.scope, h.JobID, h.ID)
	if err != nil || !view.Current || view.Handoff.State != "approved" {
		t.Fatal("refused partial cancellation changed approval", err)
	}
	if _, err := f.s.CollectionHandoffStatus(f.ctx, store.Scope{Tenant: secure.NewID(), Partner: f.scope.Partner, TokenHash: f.scope.TokenHash}, h.JobID, h.ID); err == nil {
		t.Fatal("foreign tenant read handoff")
	}
}

func TestCollectedHandoffRecipientRevocationRequiresNewWorkflowAndSeparateConsent(t *testing.T) {
	binary := routingKeyCLI(t)
	directory := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	manifest, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		t.Fatal("independent recipient public fixture required", err)
	}
	var public struct {
		Fingerprints map[string]string `json:"fingerprints"`
	}
	if json.Unmarshal(manifest, &public) != nil || public.Fingerprints["recipient"] == "" || public.Fingerprints["recipient-rsa"] == "" {
		t.Fatal("independent recipient fingerprints required")
	}
	f := setup(t)
	request := filepath.Join(t.TempDir(), "recipient.json")
	writeRequest := func(value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(request, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeRequest(map[string]any{"expected_version": 0, "purpose": "encrypt", "fingerprint": public.Fingerprints["recipient"]})
	key := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", request, "--pgp-public-file", filepath.Join(directory, "recipient-public.gpg"), "--idempotency-key", "pub-v1")
	d := f.definition()
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}
	d.Schema, d.Source = 2, &source
	d.Steps[0].Filename = "first.pgp"
	d.Steps[0].Encryption = &store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: secure.PGPEncryptMDC}
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}
	original := f.approved(t, d)
	ref := Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: ref, Timeout: 120, Authority: 1}, "recipient-handoff-source", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, job.ID, "handoff-encrypted-original-admit", Decision{Hash: job.Hash, Revision: captured.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || view.Inputs[0].RunID == nil {
		t.Fatal(err)
	}
	oldRun := *view.Inputs[0].RunID
	routingKeyCommand(t, f, binary, "pgp-key-revoke", "--pgp-key-id", key.ID, "--version", "1", "--definition-hash", key.Hash, "--expected-revision", "1", "--idempotency-key", "pub-off")
	writeRequest(map[string]any{"key_id": key.ID, "expected_version": 1, "purpose": "encrypt", "fingerprint": public.Fingerprints["recipient-rsa"]})
	newKey := routingKeyCommand(t, f, binary, "pgp-key-register", "--request-file", request, "--pgp-public-file", filepath.Join(directory, "recipient-rsa-public.gpg"), "--idempotency-key", "pub-v2")
	if newKey.ID != key.ID || newKey.Version != 2 || newKey.Fingerprint == key.Fingerprint {
		t.Fatal("replacement key changed family or retained revoked identity")
	}
	old, err := f.s.Status(f.ctx, f.scope, oldRun)
	if err != nil {
		t.Fatal(err)
	}
	worker := &delivery.Service{Custody: f.s.Custody}
	if _, _, err = worker.Claim(f.ctx, f.scope, old.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("new key silently restored old effect", err)
	}
	d.Steps[0].Encryption = &store.EncryptionPolicy{Key: store.PGPReference{ID: newKey.ID, Version: newKey.Version, Hash: newKey.Hash}, Profile: secure.PGPEncryptMDC}
	target := revisedCollectionRoutingWorkflow(t, f, original, d)
	selection := CollectionHandoffSelection{InputID: view.Inputs[0].ID, SourceRun: oldRun, Workflow: Reference{ID: target.ID, Version: target.Version, Hash: target.Hash}, Authority: 1}
	_, h := proposeCollectionHandoff(t, f, job.ID, selection)
	if _, _, err = worker.Claim(f.ctx, f.scope, old.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("proposal restored old recipient", err)
	}
	h = decideCollectionHandoff(t, f, h, "approve", "replacement-key-handoff-approve")
	h = decideCollectionHandoff(t, f, h, "execute", "replacement-key-handoff-execute")
	next, err := f.s.Status(f.ctx, f.scope, h.PlannedRunID)
	if err != nil || next.Steps[0].Attempts != 0 || next.Steps[0].Ciphertext != nil {
		t.Fatal("handoff encrypted or contacted receiver", err)
	}
	_, spec, err := worker.Claim(f.ctx, f.scope, next.Steps[0].DeliveryID, secure.NewID())
	if err != nil || spec.Encryption == nil || spec.Encryption.Key != d.Steps[0].Encryption.Key {
		t.Fatal("ordinary worker did not bind separately approved replacement key", err)
	}
	final, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
	if err != nil || !reflect.DeepEqual(final.Job, view.Job) || !reflect.DeepEqual(final.Inputs, view.Inputs) {
		t.Fatal("recipient rotation rewrote source evidence", err)
	}
}

func TestCollectedHandoffCLISavedRequestsAndReadOnlyReceiptRecoverExactSuccessor(t *testing.T) {
	binary := routingKeyCLI(t)
	f, view, selection := queuedCollectionHandoffFixture(t)
	request := filepath.Join(t.TempDir(), "handoff.json")
	write := func(value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(request, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	call := func(command string, args ...string) []byte {
		t.Helper()
		storage := f.storagePath
		if command == "workflow-collection-handoff-status" || command == "workflow-collection-handoff-list" || command == "workflow-collection-handoff-receipt" {
			storage = filepath.Join(t.TempDir(), "must-not-open-metadata-storage")
		}
		argv := []string{command, "--dsn-file", f.runtimePath, "--token-file", f.tokenPath, "--tenant", f.scope.Tenant, "--partner", f.scope.Partner, "--collection-id", view.Job.ID, "--storage", storage}
		output, err := exec.CommandContext(f.ctx, binary, append(argv, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("native handoff CLI %s: %v (diagnostic sha256 %s)", command, err, secure.Digest(output))
		}
		return output
	}
	write(selection)
	var preview CollectionHandoffPreview
	if json.Unmarshal(call("workflow-collection-handoff-preview", "--request-file", request), &preview) != nil || preview.Hash == "" {
		t.Fatal("CLI preview shape")
	}
	write(CollectionHandoffProposal{Selection: selection, Hash: preview.Hash})
	var result Result
	if json.Unmarshal(call("workflow-collection-handoff-propose", "--request-file", request, "--idempotency-key", "cli-handoff-propose"), &result) != nil {
		t.Fatal("CLI proposal shape")
	}
	h := handoffRecord(t, &result, nil)
	for _, action := range []string{"approve", "execute"} {
		write(Decision{Hash: h.Hash, Revision: h.Revision})
		if json.Unmarshal(call("workflow-collection-handoff-"+action, "--request-file", request, "--collection-handoff-id", h.ID, "--idempotency-key", "cli-handoff-"+action), &result) != nil {
			t.Fatal("CLI decision shape")
		}
		h = handoffRecord(t, &result, nil)
	}
	if h.State != "completed" {
		t.Fatal("CLI handoff did not complete")
	}
	if json.Unmarshal(call("workflow-collection-handoff-execute", "--request-file", request, "--collection-handoff-id", h.ID, "--idempotency-key", "cli-handoff-execute"), &result) != nil || !result.Replayed {
		t.Fatal("CLI lost response changed execution")
	}
	if json.Unmarshal(call("workflow-collection-handoff-receipt", "--idempotency-key", "cli-handoff-execute"), &result) != nil || !result.Replayed || handoffRecord(t, &result, nil).PlannedRunID != h.PlannedRunID {
		t.Fatal("CLI read-only receipt lost successor")
	}
	var status CollectionHandoffView
	if json.Unmarshal(call("workflow-collection-handoff-status", "--collection-handoff-id", h.ID), &status) != nil || status.Handoff == nil || status.Handoff.ID != h.ID || status.Handoff.State != "completed" {
		t.Fatal("CLI historical status required bytes")
	}
	var page store.CollectionHandoffPage
	if json.Unmarshal(call("workflow-collection-handoff-list", "--collection-limit", "1"), &page) != nil || len(page.Handoffs) != 1 || page.Handoffs[0].ID != h.ID {
		t.Fatal("CLI history lost handoff")
	}
}
