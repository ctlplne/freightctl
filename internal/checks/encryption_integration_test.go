//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func encryptedRun(t *testing.T) (*fixture, *Service, *PGPKeyView, *store.WorkflowRun, string) {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	load, fingerprints := pgpBundle(t)
	registered, err := s.RegisterPGPKey(f.ctx, f.scope, "recipient", PGPKeyRequest{Fingerprint: fingerprints["recipient"], PublicKey: load("recipient-public.gpg"), Purpose: "encrypt"})
	if err != nil {
		t.Fatal(err)
	}
	var key PGPKeyView
	if err = json.Unmarshal(registered.Resource, &key); err != nil {
		t.Fatal(err)
	}
	encryption := &store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: secure.PGPEncryptMDC}
	definition := workflow.Definition{Schema: 1, Name: "encrypted settlement", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}, Filename: "settlement.pgp", Encryption: encryption}}}
	preview, err := f.wf.Validate(f.ctx, f.scope, workflow.PreviewRequest{Definition: definition, FileID: f.file.ID})
	if err != nil || preview.Effects[0].RecipientFingerprint != key.Fingerprint || preview.Effects[0].EncryptionFingerprint != key.Recipient.Fingerprint || preview.ExternalContact {
		t.Fatal(preview, err)
	}
	draft, err := f.wf.Draft(f.ctx, f.scope, "draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var config store.Configuration
	if json.Unmarshal(draft.Resource, &config) != nil {
		t.Fatal("draft")
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, config.ID, config.Version, "approve", "approve", workflow.Decision{Hash: config.Hash, Revision: config.Revision}); err != nil {
		t.Fatal(err)
	}
	started, err := f.wf.Run(f.ctx, f.scope, "run", workflow.RunRequest{Workflow: workflow.Reference{ID: config.ID, Version: config.Version, Hash: config.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(started.Resource, &run) != nil {
		t.Fatal("run")
	}
	status, err := f.wf.Status(f.ctx, f.scope, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f, s, &key, &run, status.Steps[0].DeliveryID
}
func TestEncryptedDeliveryPersistsOneCiphertextAcrossRetryAndRejectsCorruption(t *testing.T) {
	f, _, _, run, id := encryptedRun(t)
	sender := &delivery.Service{Custody: f.wf.Custody}
	first, err := sender.Work(f.ctx, f.scope, id)
	if err != nil || first.State != "retry" {
		t.Fatal(first, err)
	}
	status, err := f.wf.Status(f.ctx, f.scope, run.ID)
	if err != nil || status.Steps[0].Ciphertext == nil {
		t.Fatal(status, err)
	}
	a := *status.Steps[0].Ciphertext
	if a.SourceID != f.file.ID || a.SourceSHA256 != f.file.SHA256 || a.SHA256 == f.file.SHA256 || a.Policy.Profile != secure.PGPEncryptMDC {
		t.Fatal(a)
	}
	if _, _, err = f.wf.Custody.Download(f.ctx, f.scope, a.ObjectID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("artifact raw ID escaped delivery owner binding", err)
	}
	report, err := f.wf.Custody.Reconcile(f.ctx, f.scope)
	if err != nil || !report.Consistent || report.Counts["verified_ciphertext"] != 1 {
		t.Fatal(report, err)
	}
	time.Sleep(time.Until(first.NextAt.Add(20 * time.Millisecond)))
	second, err := sender.Work(f.ctx, f.scope, id)
	if err != nil || second.State != "retry" || second.Fence != first.Fence+1 {
		t.Fatal(second, err)
	}
	status, err = f.wf.Status(f.ctx, f.scope, run.ID)
	if err != nil || status.Steps[0].Ciphertext.ObjectID != a.ObjectID || status.Steps[0].Ciphertext.SHA256 != a.SHA256 || status.Steps[0].Ciphertext.Fence != a.Fence {
		t.Fatal("retry regenerated ciphertext", status, err)
	}
	path := filepath.Join(f.diskPath, custody.Name(f.scope.Tenant, f.scope.Partner, a.ObjectID))
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("corrupt"), 0400); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(second.NextAt.Add(20 * time.Millisecond)))
	third, err := sender.Work(f.ctx, f.scope, id)
	if err != nil || third.State != "retry" {
		t.Fatal(third, err)
	}
	var observation map[string]string
	if json.Unmarshal(third.Observation, &observation) != nil || observation["code"] != "encryption_preparation_unavailable" {
		t.Fatal(third)
	}
	report, err = f.wf.Custody.Reconcile(f.ctx, f.scope)
	if err != nil || report.Counts["ciphertext_integrity_mismatch"] != 1 {
		t.Fatal(report, err)
	}
}
func TestEncryptedPublicationRequiresArtifactAndLiveRecipient(t *testing.T) {
	f, s, key, run, id := encryptedRun(t)
	sender := &delivery.Service{Custody: f.wf.Custody}
	claimed, _, err := sender.Claim(f.ctx, f.scope, id, secure.NewID())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.wf.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	d, err := tx.Delivery(f.ctx, id, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := d.Revision
	d.Revision++
	d.State = "publishing"
	if err = tx.SaveDelivery(f.ctx, d, previous); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil || !strings.Contains(err.Error(), "encrypted publication requires exact durable ciphertext proof") {
		t.Fatal("publication skipped durable ciphertext proof")
	}
	tx, err = f.wf.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	artifact := &store.DeliveryCiphertext{DeliveryID: id, ObjectID: secure.NewID(), StorageID: f.wf.Custody.Disk.Identity(), Size: 100, SHA256: secure.Digest([]byte("wrong")), SourceID: f.file.ID, SourceSHA256: f.file.SHA256, DefinitionHash: claimed.DefinitionHash, Policy: store.EncryptionPolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, Profile: secure.PGPEncryptMDC}, Fence: claimed.Fence, Owner: secure.NewID()}
	if err = tx.SaveDeliveryCiphertext(f.ctx, artifact); err == nil || !strings.Contains(err.Error(), "ciphertext must bind live worker") {
		t.Fatal("forged worker ciphertext accepted")
	}
	_ = tx.Tx.Rollback(f.ctx)
	if _, err = s.RevokePGPKey(f.ctx, f.scope, key.ID, key.Version, "revoke-recipient", workflow.Decision{Hash: key.Hash, Revision: key.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, _, err = sender.Claim(f.ctx, f.scope, id, secure.NewID()); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked recipient admitted", err)
	}
	status, err := f.wf.Status(f.ctx, f.scope, run.ID)
	if err != nil || status.ObservedReason != "encryption_recipient_unavailable" {
		t.Fatal(status, err)
	}
	policy := testPolicy(t)
	policy.Signature = &SignaturePolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}}
	if _, err = s.Register(f.ctx, f.scope, "recipient-is-not-signer", PolicyRequest{Definition: policy}); err == nil {
		t.Fatal("encryption recipient became verification identity")
	}
}
func TestCiphertextJournalFailureRetainsOnlyUnreferencedBytes(t *testing.T) {
	f, _, _, _, id := encryptedRun(t)
	sender := &delivery.Service{Custody: f.wf.Custody}
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_ciphertext_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'task-owned ciphertext projection failure';END $$;CREATE TRIGGER freightctl_test_ciphertext_failure BEFORE INSERT ON delivery_ciphertexts FOR EACH ROW EXECUTE FUNCTION freightctl_test_ciphertext_failure()`); err != nil {
		t.Fatal(err)
	}
	d, err := sender.Work(f.ctx, f.scope, id)
	if err != nil || d.State != "retry" {
		t.Fatal(d, err)
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM delivery_ciphertexts`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='DeliveryCiphertextPrepared'`).Scan(&n); err != nil || n != 0 {
		t.Fatal("ciphertext event escaped failed transaction", n, err)
	}
	report, err := f.wf.Custody.Reconcile(f.ctx, f.scope)
	if err != nil || report.Counts["unreferenced_bytes"] != 1 || report.Counts["verified_ciphertext"] != 0 {
		t.Fatal(report, err)
	}
}

func TestEncryptionSlotsAndCustodyReservationDoNotConsumeTransferSlots(t *testing.T) {
	f := setup(t)
	_, release1, err := f.wf.Custody.DB.EncryptionWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()
	_, release2, err := f.wf.Custody.DB.EncryptionWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if _, release, err := f.wf.Custody.DB.EncryptionWorkerSlot(f.ctx); !errors.Is(err, store.ErrLimit) {
		if release != nil {
			release()
		}
		t.Fatal("encryption slot bound", err)
	}
	_, transfer, err := f.wf.Custody.DB.DeliveryWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal("encryption consumed transfer slots", err)
	}
	defer transfer()
	_, reservation, err := f.wf.Custody.DB.CustodyGenerationSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reservation()
	tx, err := f.wf.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var locked bool
	if err = tx.Tx.QueryRow(f.ctx, `SELECT pg_try_advisory_xact_lock(721815034)`).Scan(&locked); err != nil || locked {
		t.Fatal("ordinary acceptance ignored ciphertext quota reservation", locked, err)
	}
}
