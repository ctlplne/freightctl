//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func recheckRow(t *testing.T, r *Result) *store.FileRecheck {
	t.Helper()
	var v struct {
		Kind    string             `json:"kind"`
		Recheck *store.FileRecheck `json:"recheck"`
	}
	if json.Unmarshal(r.Resource, &v) != nil || v.Kind != "file_recheck" || v.Recheck == nil {
		t.Fatal("invalid recheck receipt")
	}
	return v.Recheck
}

func proposedRecheck(t *testing.T, s *Service, f *fixture, id, key string) *store.FileRecheck {
	t.Helper()
	v, err := s.PreviewRecheck(f.ctx, f.scope, id, RecheckOptions{SignatureMode: "not_required", Reason: "Review current policy without changing original evidence"})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.ProposeRecheck(f.ctx, f.scope, key, v.Plan)
	if err != nil {
		t.Fatal(err)
	}
	return recheckRow(t, saved)
}

func TestRecheckPreviewApprovalCancellationAndPrivateHistory(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, true)
	v, err := s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "Review the exact original file"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*RecheckPlan){
		func(p *RecheckPlan) { p.Source.File.SHA256 = secure.Digest([]byte("different")) },
		func(p *RecheckPlan) { p.Source.Check.Attempts++ },
		func(p *RecheckPlan) { p.Source.Check.Code = "invented" },
		func(p *RecheckPlan) { p.Policy.Version++ },
		func(p *RecheckPlan) { p.Authority++ },
		func(p *RecheckPlan) { p.StorageID = secure.NewID() },
	} {
		data, _ := json.Marshal(v.Plan)
		var p RecheckPlan
		_ = json.Unmarshal(data, &p)
		mutate(&p)
		if _, e := s.ProposeRecheck(f.ctx, f.scope, secure.NewID(), p); !errors.Is(e, store.ErrRevision) {
			t.Fatal("tampered plan accepted", e)
		}
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM file_rechecks`).Scan(&count); err != nil || count != 0 {
		t.Fatal("preview or refusal saved state", count, err)
	}
	saved, err := s.ProposeRecheck(f.ctx, f.scope, "save", v.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r := recheckRow(t, saved)
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "unapproved-copy"); !errors.Is(err, store.ErrState) {
		t.Fatal("unapproved copy", err)
	}
	replayed, err := s.ProposeRecheck(f.ctx, f.scope, "save", v.Plan)
	if err != nil || !replayed.Replayed || !bytes.Equal(saved.Resource, replayed.Resource) {
		t.Fatal("proposal receipt drift", err)
	}
	changed := v.Plan
	changed.Reason = "Another meaning for the same key"
	if _, err = s.ProposeRecheck(f.ctx, f.scope, "save", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("key collision accepted", err)
	}
	if _, err = s.DecideRecheck(f.ctx, f.scope, r.ID, "bad-hash", PolicyRecheckDecision{Operation: "approve", Hash: strings.Repeat("f", 64), Revision: r.Revision}); !errors.Is(err, store.ErrRevision) {
		t.Fatal(err)
	}
	cancelled, err := s.DecideRecheck(f.ctx, f.scope, r.ID, "cancel", PolicyRecheckDecision{Operation: "cancel", Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(err)
	}
	r = recheckRow(t, cancelled)
	if _, err = s.DecideRecheck(f.ctx, f.scope, r.ID, "revive", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("cancellation revived", err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "cancelled-copy"); !errors.Is(err, store.ErrState) {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner}
	token := t.TempDir() + "/token"
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, other.Tenant, other.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	if _, err = s.GetRecheck(f.ctx, other, r.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign actor read intent", err)
	}
	if _, err = s.ListRechecks(f.ctx, other, source.ID, "", 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign actor listed source", err)
	}
	if _, err = s.PreviewRecheck(f.ctx, other, source.ID, optionsForRecheck(v.Plan)); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign actor used source", err)
	}
	for i := 0; i < 3; i++ {
		proposedRecheck(t, s, f, source.ID, fmt.Sprintf("history-%d", i))
	}
	page, err := s.ListRechecks(f.ctx, f.scope, source.ID, "", 2)
	if err != nil || len(page.Rechecks) != 2 || page.Next == "" {
		t.Fatal(page, err)
	}
	last, err := s.ListRechecks(f.ctx, f.scope, source.ID, page.Next, 2)
	if err != nil || len(last.Rechecks) != 2 || last.Next != "" || page.Rechecks[1].ID >= last.Rechecks[0].ID {
		t.Fatal(last, err)
	}
}

func TestRecheckRefusesStalePolicyLiveWorkerAndChangedTarget(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, true)
	r := proposedRecheck(t, s, f, source.ID, "stale")
	p := testPolicy(t)
	p.MaxRows--
	if _, err := s.Register(f.ctx, f.scope, "policy-two", PolicyRequest{ExpectedVersion: 1, Definition: p}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideRecheck(f.ctx, f.scope, r.ID, "stale-approve", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale policy approved", err)
	}
	v, err := s.GetRecheck(f.ctx, f.scope, r.ID)
	if err != nil || v.Current {
		t.Fatal("stale plan current", err)
	}
	r = approvedRecheck(t, s, f, source.ID, "not_required")
	if _, _, err = s.Custody.AcceptAt(f.ctx, f.scope, "occupy-target", int64(len(goodCSV)), source.SHA256, strings.NewReader(goodCSV), custody.UploadTarget{Path: "/checked.csv"}); err != nil {
		t.Fatal(err)
	}
	// A new held upload has not published the target. Explicit namespace change
	// instead creates a directory there, invalidating the reviewed selector.
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "changed-target", store.PathCommand{Operation: "mkdir", Path: "/checked.csv"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "changed-target-copy"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed target copied", err)
	}
	// The original source still uses its retired policy. A fresh source under
	// the active policy provides an actual live check reservation.
	newFile, _, err := s.Custody.Accept(f.ctx, f.scope, "new-worker-source", int64(len(goodCSV)), source.SHA256, strings.NewReader(goodCSV))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err = s.start(f.ctx, f.scope, newFile.ID, "live-worker"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewRecheck(f.ctx, f.scope, newFile.ID, RecheckOptions{SignatureMode: "not_required", Reason: "Do not bypass a live worker"}); !errors.Is(err, store.ErrState) {
		t.Fatal("live lease bypassed", err)
	}
}

func TestRecheckReceiptRollbackRetainsCompleteObjectsAndCommitsOnce(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, false)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	d, err := decodeRecheck(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_recheck_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result->'recheck'->>'state'='copied' THEN RAISE EXCEPTION 'task-owned copy receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_test_recheck_receipt_failure BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_recheck_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "copy"); err == nil {
		t.Fatal("receipt failure ignored")
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files WHERE file_id=$1)+(SELECT count(*) FROM events WHERE resource_id=$1)+(SELECT count(*) FROM check_receipts WHERE request_key='copy')`, d.Slots[0].FileID).Scan(&n); err != nil || n != 0 {
		t.Fatal("partial SQL commit", n, err)
	}
	st, err := os.Stat(f.diskPath + "/" + custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[0].FileID))
	if err != nil || st.Mode().Perm() != 0400 || st.Size() != source.Size {
		t.Fatal("durable orphan missing", err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_recheck_receipt_failure ON check_receipts;DROP FUNCTION freightctl_test_recheck_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "copy")
	if err != nil {
		t.Fatal(err)
	}
	if recheckRow(t, result).FileID != d.Slots[0].FileID {
		t.Fatal("known complete object not adopted")
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE resource_id=$1 AND kind='FileAccepted'`, d.Slots[0].FileID).Scan(&n); err != nil || n != 1 {
		t.Fatal("multiple acceptances", n, err)
	}
}

func TestRecheckExhaustionTamperingAdmissionAndQueueBounds(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, false)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	d, err := decodeRecheck(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range d.Slots {
		if err = os.WriteFile(f.diskPath+"/"+custody.Name(f.scope.Tenant, f.scope.Partner, slot.FileID), []byte("partial"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "exhausted"); !errors.Is(err, store.ErrLimit) {
		t.Fatal(err)
	}
	other := proposedRecheck(t, s, f, source.ID, "tamper")
	a, err := s.DecideRecheck(f.ctx, f.scope, other.ID, "approve-other", PolicyRecheckDecision{Operation: "approve", Hash: other.Hash, Revision: other.Revision})
	if err != nil {
		t.Fatal(err)
	}
	other = recheckRow(t, a)
	d, err = decodeRecheck(other)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(f.diskPath+"/"+custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[0].FileID), []byte("wrong immutable bytes"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, other.ID, "tampered-copy"); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal(err)
	}
	_, free1, err := s.Custody.DB.RecheckCopySlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer free1()
	_, free2, err := s.Custody.DB.RecheckCopySlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer free2()
	if _, err = s.CopyRecheck(f.ctx, f.scope, other.ID, "busy-copy"); !errors.Is(err, store.ErrLimit) {
		t.Fatal("unbounded copy workers", err)
	}
	for i := 2; i < 16; i++ {
		proposedRecheck(t, s, f, source.ID, fmt.Sprintf("bounded-%d", i))
	}
	v, err := s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "One proposal exceeds the fixed actor queue"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProposeRecheck(f.ctx, f.scope, "overflow", v.Plan); !errors.Is(err, store.ErrLimit) {
		t.Fatal("unbounded intent queue", err)
	}
}

func TestRecheckSignatureRebindRetainsControlsAndFreshVerification(t *testing.T) {
	f, s, key, source, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, source.ID)
	if _, err := s.AttachSignature(f.ctx, f.scope, source.ID, "attach", source.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(f.ctx, f.scope, source.ID, "original-check"); err != nil {
		t.Fatal(err)
	}
	before := getCheck(t, s, f, source.ID)
	p := testPolicy(t)
	p.Signature = &SignaturePolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, MaxAgeSeconds: 1800}
	if _, err := s.Register(f.ctx, f.scope, "policy-two", PolicyRequest{ExpectedVersion: 1, Definition: p}); err != nil {
		t.Fatal(err)
	}
	r := approvedRecheck(t, s, f, source.ID, "reuse_exact")
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "signed-copy")
	if err != nil {
		t.Fatal(err)
	}
	child := recheckRow(t, result).FileID
	if getCheck(t, s, f, child).Attempts != 0 {
		t.Fatal("signature reused a verdict")
	}
	if _, err = s.Run(f.ctx, f.scope, child, "fresh-check"); err != nil {
		t.Fatal(err)
	}
	checked := getCheck(t, s, f, child)
	if checked.State != "passed" || checked.Attempts != 1 {
		t.Fatal(checked.State)
	}
	a, _ := json.Marshal(before)
	b, _ := json.Marshal(getCheck(t, s, f, source.ID))
	if !sameJSON(a, b) {
		t.Fatal("original evidence changed")
	}
	p.Signature.MaxAgeSeconds = 3600
	if _, err = s.Register(f.ctx, f.scope, "looser-age", PolicyRequest{ExpectedVersion: 2, Definition: p}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewRecheck(f.ctx, f.scope, child, RecheckOptions{SignatureMode: "reuse_exact", Reason: "Cannot loosen previous signature age"}); !errors.Is(err, ErrInput) {
		t.Fatal("weaker age accepted", err)
	}
	p.Signature = nil
	if _, err = s.Register(f.ctx, f.scope, "remove-control", PolicyRequest{ExpectedVersion: 3, Definition: p}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "Cannot drop the signature control"}); !errors.Is(err, ErrInput) {
		t.Fatal("control removed", err)
	}
	if _, err = s.RevokePGPKey(f.ctx, f.scope, key.ID, key.Version, "revoke", workflow.Decision{Hash: key.Hash, Revision: key.Revision}); err != nil {
		t.Fatal(err)
	}
}

func TestRecheckRuntimeSQLGuardsImmutableSlotsAndAtomicCompletion(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, false)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	d, err := decodeRecheck(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE file_rechecks SET definition=jsonb_set(definition,'{plan,reason}','"tampered reason"') WHERE recheck_id=$1`,
		`UPDATE file_rechecks SET state='cancelled',revision=revision+1 WHERE recheck_id=$1`,
		`UPDATE file_recheck_slots SET file_id=gen_random_uuid() WHERE recheck_id=$1`,
		`DELETE FROM file_recheck_slots WHERE recheck_id=$1`,
		`DELETE FROM file_rechecks WHERE recheck_id=$1`,
	} {
		tx, e := s.recheckBegin(f.ctx, f.scope)
		if e != nil {
			t.Fatal(e)
		}
		_, e = tx.Tx.Exec(f.ctx, query, r.ID)
		tx.Tx.Rollback(f.ctx)
		if e == nil {
			t.Fatal("ordinary runtime bypassed immutable projection guard")
		}
	}
	// The application runtime can stage and bind real bytes, but SQL must refuse
	// a commit which omits the corresponding completion and receipt path.
	if err = s.Custody.Disk.Stage(custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[0].FileID), strings.NewReader(goodCSV), source.Size, source.SHA256); err != nil {
		t.Fatal(err)
	}
	tx, err := s.recheckBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	file := store.File{ID: d.Slots[0].FileID, Size: source.Size, SHA256: source.SHA256}
	if err = tx.ConfigureIntakeFile(f.ctx, &file); err != nil {
		t.Fatal(err)
	}
	if err = tx.AcceptRecheckedFile(f.ctx, r, &file, s.Custody.Disk.Identity()); err != nil {
		t.Fatal(err)
	}
	if held, e := tx.BindIntake(f.ctx, &file, s.Custody.Disk.Identity(), nil); e != nil || !held {
		t.Fatal(e)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("derived file committed without atomic intent completion")
	}
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "copy-after-refused-commit")
	if err != nil || recheckRow(t, result).FileID != d.Slots[0].FileID {
		t.Fatal("refused commit prevented exact orphan recovery", err)
	}
}

func TestRecheckIntegrityOnlySourceRequiresNewHeldChecks(t *testing.T) {
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	if _, err := s.Register(f.ctx, f.scope, "policy", PolicyRequest{Definition: testPolicy(t)}); err != nil {
		t.Fatal(err)
	}
	r := approvedRecheck(t, s, f, f.file.ID, "not_required")
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "legacy-copy")
	if err != nil {
		t.Fatal(err)
	}
	child := recheckRow(t, result).FileID
	if _, err = s.Run(f.ctx, f.scope, child, "check-invalid-csv"); err != nil {
		t.Fatal(err)
	}
	if getCheck(t, s, f, child).State != "rejected" {
		t.Fatal("legacy integrity receipt became a valid CSV verdict")
	}
	_, reader, err := s.Custody.Download(f.ctx, f.scope, f.file.ID)
	if err != nil {
		t.Fatal("original integrity scope changed", err)
	}
	reader.Close()
}

func TestRecheckRefusesChangedProtectedStorageIdentity(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, false)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	marker := f.diskPath + "/" + custody.StorageIdentityName
	if err := os.Chmod(marker, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte(secure.NewID()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "Changed storage must require fresh review"}); !errors.Is(err, custody.ErrStorageIdentity) {
		t.Fatal("changed store preview accepted", err)
	}
	if _, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "changed-store-copy"); !errors.Is(err, custody.ErrStorageIdentity) {
		t.Fatal("changed store copied", err)
	}
}

func TestRecheckAuthorityLifecycleAndPrivateAudit(t *testing.T) {
	f := setup(t)
	s, _, _ := policyAndFile(t, f, goodCSV, false)
	manager := f.scope
	grants := []string{"admin", "read", "write", "intake_manage", "check_run", "check_release"}
	command := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Recheck operator", Root: "/", Permissions: grants}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, manager, "operator", command); err != nil {
		t.Fatal(err)
	}
	f.scope = store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: command.CredentialHash}
	source, _, err := s.Custody.Accept(f.ctx, f.scope, "operator-source", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV))
	if err != nil {
		t.Fatal(err)
	}
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	change := store.AccountCommand{Operation: "update", ID: command.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Recheck operator", Root: "/", Permissions: grants[:5]}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, manager, "remove-release", change); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "revoked-authority-copy"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("removed grant copied", err)
	}
	if _, err = s.GetRecheck(f.ctx, f.scope, r.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("removed grant read private intent", err)
	}
	change.ExpectedRevision = 2
	change.Policy.Permissions = grants
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, manager, "restore-release", change); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "stale-authority-copy"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("restored grant revived old review", err)
	}
	v, err := s.GetRecheck(f.ctx, f.scope, r.ID)
	if err != nil || v.Current {
		t.Fatal("old authority review current", err)
	}
	preview, err := s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "SYNTHETIC_PRIVATE_RECHECK_REASON"})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.ProposeRecheck(f.ctx, f.scope, "private-reason", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	private := recheckRow(t, saved)
	events, err := s.Custody.DB.Events(f.ctx, manager)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Custody.DB.SnapshotEvents(f.ctx, manager, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]store.Event{events, snapshot.Events} {
		seen := 0
		for _, event := range list {
			if event.ResourceID != private.ID {
				continue
			}
			seen++
			if bytes.Contains(event.Payload, []byte(preview.Plan.Reason)) || !bytes.Contains(event.Payload, []byte(`"redacted":true`)) {
				t.Fatal("ordinary audit disclosed private reason")
			}
		}
		if seen != 2 {
			t.Fatal("missing private proposal/receipt audit events", seen)
		}
	}
}

func TestRecheckNewSignerRequiresNewAttachmentAndFreshVerification(t *testing.T) {
	f, s, _, source, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, source.ID)
	if _, err := s.AttachSignature(f.ctx, f.scope, source.ID, "old-signature", source.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	load, fingerprints := pgpBundle(t)
	registered, err := s.RegisterPGPKey(f.ctx, f.scope, "new-key", PGPKeyRequest{Fingerprint: fingerprints["other"], PublicKey: load("other-public.gpg")})
	if err != nil {
		t.Fatal(err)
	}
	var key PGPKeyView
	if json.Unmarshal(registered.Resource, &key) != nil {
		t.Fatal("key")
	}
	p := testPolicy(t)
	p.Signature = &SignaturePolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, MaxAgeSeconds: 1800}
	if _, err = s.Register(f.ctx, f.scope, "new-signer-policy", PolicyRequest{ExpectedVersion: 1, Definition: p}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "reuse_exact", Reason: "Old signature cannot select a new signer"}); !errors.Is(err, ErrInput) {
		t.Fatal("different signer reused", err)
	}
	r := approvedRecheck(t, s, f, source.ID, "require_new")
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "new-signature-copy")
	if err != nil {
		t.Fatal(err)
	}
	child := recheckRow(t, result).FileID
	if _, err = s.Run(f.ctx, f.scope, child, "missing-new-signature"); !errors.Is(err, store.ErrState) {
		t.Fatal("missing signature bypassed", err)
	}
	c = getCheck(t, s, f, child)
	if c.Attempts != 0 {
		t.Fatal("missing signature consumed attempt")
	}
	if _, err = s.AttachSignature(f.ctx, f.scope, child, "new-signature", source.SHA256, c.PolicyHash, c.Revision, load("other.sig")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, f.scope, child, "new-signer-check"); err != nil {
		t.Fatal(err)
	}
	if getCheck(t, s, f, child).State != "passed" {
		t.Fatal("new signature not verified")
	}
}

func TestRecheckScannerDriftRevocationAndRequiredControl(t *testing.T) {
	f, s, scanner, source, definition := scanFixture(t, "offline", time.Hour)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	config, err := os.ReadFile(definition.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(definition.Configuration, append(bytes.Clone(config), []byte("\n# changed\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "drift-copy"); err == nil {
		t.Fatal("scanner drift copied")
	}
	if err = os.WriteFile(definition.Configuration, config, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeScanner(f.ctx, f.scope, scanner.ID, scanner.Version, "revoke-scanner", workflow.Decision{Hash: scanner.Hash, Revision: scanner.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "revoked-scanner-copy"); err == nil {
		t.Fatal("revoked scanner copied")
	}
	if _, err = s.Register(f.ctx, f.scope, "drop-scanner-policy", PolicyRequest{ExpectedVersion: 1, Definition: testPolicy(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{SignatureMode: "not_required", Reason: "Cannot drop the original scanner control"}); !errors.Is(err, ErrInput) {
		t.Fatal("scanner control removed", err)
	}
}
func approvedRecheck(t *testing.T, s *Service, f *fixture, id string, mode string) *store.FileRecheck {
	t.Helper()
	v, err := s.PreviewRecheck(f.ctx, f.scope, id, RecheckOptions{TargetPath: "/checked.csv", SignatureMode: mode, Reason: "Refresh checks under the reviewed current policy"})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := s.ProposeRecheck(f.ctx, f.scope, "propose", v.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r := recheckRow(t, saved)
	result, err := s.DecideRecheck(f.ctx, f.scope, r.ID, "approve", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return recheckRow(t, result)
}
func TestRecheckCreatesExactHeldRevisionWithoutChangingOriginalEvidence(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, true)
	before := getCheck(t, s, f, source.ID)
	p := testPolicy(t)
	p.MaxRows--
	if _, err := s.Register(f.ctx, f.scope, "new-policy", PolicyRequest{ExpectedVersion: 1, Definition: p}); err != nil {
		t.Fatal(err)
	}
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "copy")
	if err != nil {
		t.Fatal(err)
	}
	copied := recheckRow(t, result)
	var got RecheckCopyResult
	if json.Unmarshal(copied.Result, &got) != nil || got.File.ID == source.ID || got.File.SHA256 != source.SHA256 || got.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal(got)
	}
	after := getCheck(t, s, f, source.ID)
	a, _ := json.Marshal(after)
	b, _ := json.Marshal(before)
	if !sameJSON(a, b) {
		t.Fatal("original check changed")
	}
	child := getCheck(t, s, f, got.File.ID)
	if child.State != "held" || child.Attempts != 0 || child.PolicyHash == before.PolicyHash {
		t.Fatal(child)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, got.File.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("copy published bytes", err)
	}
	_, free1, err := f.wf.Custody.DB.RecheckCopySlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer free1()
	_, free2, err := f.wf.Custody.DB.RecheckCopySlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer free2()
	replay, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "copy")
	if err != nil || !replay.Replayed || !bytes.Equal(replay.Resource, result.Resource) {
		t.Fatal("copied receipt depends on copy admission", err)
	}
	if _, err = s.Run(f.ctx, f.scope, got.File.ID, "check-child"); err != nil {
		t.Fatal(err)
	}
	child = getCheck(t, s, f, got.File.ID)
	if _, err = s.Release(f.ctx, f.scope, got.File.ID, "release-child", releaseDecision(child)); err != nil {
		t.Fatal(err)
	}
	_, data, err := s.Custody.DownloadPath(f.ctx, f.scope, "/checked.csv")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(data)
	data.Close()
	if err != nil || string(actual) != goodCSV {
		t.Fatal(err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, source.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("original quarantine waived", err)
	}
}
func TestRecheckRetainsPartialSlotAndAdoptsOnlyVerifiedIntentObjects(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, true)
	r := approvedRecheck(t, s, f, source.ID, "not_required")
	d, err := decodeRecheck(r)
	if err != nil {
		t.Fatal(err)
	}
	// A real interrupted-stage-shaped object is retained, not overwritten.
	partial := custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[0].FileID)
	path := f.diskPath + "/" + partial
	if err = os.WriteFile(path, []byte("partial bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	// A complete, synced known-intent object can be adopted after SQL rollback.
	if err = s.Custody.Disk.Stage(custody.Name(f.scope.Tenant, f.scope.Partner, d.Slots[1].FileID), strings.NewReader(goodCSV), int64(len(goodCSV)), secure.Digest([]byte(goodCSV))); err != nil {
		t.Fatal(err)
	}
	result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "copy")
	if err != nil {
		t.Fatal(err)
	}
	copied := recheckRow(t, result)
	if copied.FileID != d.Slots[1].FileID {
		t.Fatal("wrong staging slot selected")
	}
	left, err := os.ReadFile(path)
	if err != nil || string(left) != "partial bytes" {
		t.Fatal("partial was altered", err)
	}
}
