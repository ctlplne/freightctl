//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func pgpBundle(t *testing.T) (func(string) []byte, map[string]string) {
	t.Helper()
	dir := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	if dir == "" {
		t.Fatal("independent GnuPG fixture reference required")
	}
	load := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var manifest struct {
		Fingerprints map[string]string `json:"fingerprints"`
	}
	if json.Unmarshal(load("manifest.json"), &manifest) != nil {
		t.Fatal("fixture manifest")
	}
	return load, manifest.Fingerprints
}
func signedIntake(t *testing.T, source []byte) (*fixture, *Service, *PGPKeyView, *store.File, []byte) {
	t.Helper()
	load, fingerprints := pgpBundle(t)
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	registered, err := s.RegisterPGPKey(f.ctx, f.scope, "pgp-key", PGPKeyRequest{Fingerprint: fingerprints["good"], PublicKey: load("good-public.gpg")})
	if err != nil {
		t.Fatal(err)
	}
	var key PGPKeyView
	if json.Unmarshal(registered.Resource, &key) != nil {
		t.Fatal("key registration result")
	}
	policy := testPolicy(t)
	policy.Signature = &SignaturePolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, MaxAgeSeconds: 3600}
	if _, err = s.Register(f.ctx, f.scope, "policy", PolicyRequest{Definition: policy}); err != nil {
		t.Fatal(err)
	}
	if source == nil {
		source = load("source.csv")
	}
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "signed-source", int64(len(source)), secure.Digest(source), bytes.NewReader(source), custody.UploadTarget{Path: "/signed.csv"})
	if err != nil {
		t.Fatal(err)
	}
	return f, s, &key, file, load("good.sig")
}
func TestSignedIntakeNeedsBoundSignatureAndLiveSigner(t *testing.T) {
	f, s, key, file, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, file.ID)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "missing-signature"); !errors.Is(err, store.ErrState) {
		t.Fatal("missing signature consumed an attempt", err)
	}
	if getCheck(t, s, f, file.ID).Attempts != 0 {
		t.Fatal("missing prerequisite spent an attempt")
	}
	attached, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire)
	if err != nil || !again.Replayed || !sameJSON(attached.Resource, again.Resource) {
		t.Fatal(again, err)
	}
	if _, err = s.AttachSignature(f.ctx, f.scope, file.ID, "substitute", file.SHA256, c.PolicyHash, c.Revision, append(bytes.Clone(wire), wire...)); !errors.Is(err, ErrInput) {
		t.Fatal("mixed signature accepted", err)
	}
	if _, err = s.Run(f.ctx, f.scope, file.ID, "check"); err != nil {
		t.Fatal(err)
	}
	c = getCheck(t, s, f, file.ID)
	var report Report
	if json.Unmarshal(c.Report, &report) != nil || c.State != "passed" || report.Signature == nil || report.Signature.Verification.PrimaryFingerprint != key.Fingerprint {
		t.Fatal(c)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("signature pass bypassed release", err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c)); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.OpenPathReader(f.ctx, f.scope, "/signed.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	observed, data, err := s.SignatureContent(f.ctx, f.scope, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(data)
	data.Close()
	if err != nil || !bytes.Equal(actual, wire) || observed.SHA256 != secure.Digest(wire) {
		t.Fatal(err)
	}
	reconciliation, err := s.Custody.Reconcile(f.ctx, f.scope)
	if err != nil || !reconciliation.Consistent || reconciliation.Counts["verified_signature"] != 1 {
		t.Fatal(reconciliation, err)
	}
	if _, err = s.RevokePGPKey(f.ctx, f.scope, key.ID, key.Version, "revoke-signer", workflow.Decision{Hash: key.Hash, Revision: key.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ReadAt(make([]byte, 1), 1); !errors.Is(err, store.ErrState) {
		t.Fatal("open reader ignored signer revocation", err)
	}
	if view, err := s.Get(f.ctx, f.scope, file.ID); err != nil || view.Current {
		t.Fatal(view, err)
	}
}
func TestIndependentBadSignaturesNeverRelease(t *testing.T) {
	for _, kind := range []string{"wrong_key", "changed_data", "aged"} {
		t.Run(kind, func(t *testing.T) {
			load, _ := pgpBundle(t)
			var source []byte
			if kind == "changed_data" {
				source = bytes.Replace(load("source.csv"), []byte("100.01"), []byte("100.02"), 1)
			}
			f, s, _, file, wire := signedIntake(t, source)
			if kind == "wrong_key" {
				wire = load("other.sig")
			}
			if kind == "aged" {
				wire = load("aged.sig")
			}
			c := getCheck(t, s, f, file.ID)
			if _, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Run(f.ctx, f.scope, file.ID, "check"); err != nil {
				t.Fatal(err)
			}
			c = getCheck(t, s, f, file.ID)
			if c.State != "rejected" || c.Code != "signature_invalid" {
				t.Fatal(c)
			}
			if _, _, err := s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
				t.Fatal(err)
			}
		})
	}
}
func TestSignatureArtifactsArePrivateImmutableAndReverified(t *testing.T) {
	f, s, _, file, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, file.ID)
	if _, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(f.ctx, f.scope, file.ID, "check"); err != nil {
		t.Fatal(err)
	}
	c = getCheck(t, s, f, file.ID)
	view, err := s.Get(f.ctx, f.scope, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(f.diskPath, custody.Name(f.scope.Tenant, f.scope.Partner, view.Signature.ObjectID))
	if err = os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, bytes.Repeat([]byte("x"), len(wire)), 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(name, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "changed-signature", releaseDecision(c)); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("changed sidecar released", err)
	}
	token := filepath.Join(t.TempDir(), "other.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := f.scope
	other.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	if _, _, err = s.SignatureContent(f.ctx, other, file.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor saw sidecar", err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `UPDATE file_signatures SET sha256=$1 WHERE file_id=$2`, strings.Repeat("0", 64), file.ID); err == nil {
		t.Fatal("signature artifact was mutable")
	}
	_ = tx.Tx.Rollback(f.ctx)
}

func TestSignatureReceiptFailureAndKeyMaterialCannotBypassJournal(t *testing.T) {
	f, s, key, file, wire := signedIntake(t, nil)
	c := getCheck(t, s, f, file.ID)
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_signature_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result ? 'object_id' THEN RAISE EXCEPTION 'task-owned signature receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_test_signature_receipt_failure BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_signature_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire); err == nil {
		t.Fatal("failed receipt allowed signature attachment")
	}
	var count int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM file_signatures`).Scan(&count); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	if _, err := f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_signature_receipt_failure ON check_receipts;DROP FUNCTION freightctl_test_signature_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	report, err := s.Custody.Reconcile(f.ctx, f.scope)
	if err != nil || report.Counts["verified_signature"] != 1 || report.Counts["unreferenced_bytes"] != 1 {
		t.Fatal(report, err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	row, err := tx.PGPKey(f.ctx, key.ID, key.Version, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := row.Revision
	row.Revision++
	row.State = "revoked"
	row.Definition = json.RawMessage(`{}`)
	if err = tx.SavePGPKey(f.ctx, row, previous); err == nil {
		t.Fatal("registered key material was mutable")
	}
	_ = tx.Tx.Rollback(f.ctx)
}
