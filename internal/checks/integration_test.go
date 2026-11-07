//go:build integration

package checks

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

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

const goodCSV = "account,amount,day\n0001,1.01,2026-10-28\n"

func policyAndFile(t *testing.T, f *fixture, text string, target bool) (*Service, *store.Configuration, *store.File) {
	t.Helper()
	s := &Service{Custody: f.wf.Custody}
	result, err := s.Register(f.ctx, f.scope, "policy", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var p store.Configuration
	if json.Unmarshal(result.Resource, &p) != nil {
		t.Fatal("policy response")
	}
	var file *store.File
	if target {
		file, _, err = f.wf.Custody.AcceptAt(f.ctx, f.scope, "held", int64(len(text)), secure.Digest([]byte(text)), strings.NewReader(text), custody.UploadTarget{Path: "/checked.csv"})
	} else {
		file, _, err = f.wf.Custody.Accept(f.ctx, f.scope, "held", int64(len(text)), secure.Digest([]byte(text)), strings.NewReader(text))
	}
	if err != nil {
		t.Fatal(err)
	}
	if file.Policy != "intake-csv-v1:"+p.Hash {
		t.Fatal(file)
	}
	return s, &p, file
}
func getCheck(t *testing.T, s *Service, f *fixture, id string) *store.FileCheck {
	t.Helper()
	view, err := s.Get(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	return view.Check
}
func releaseDecision(c *store.FileCheck) ReleaseDecision {
	var b store.CheckBinding
	_ = json.Unmarshal(c.Binding, &b)
	return ReleaseDecision{SHA256: b.File.SHA256, PolicyHash: c.PolicyHash, ReportHash: c.ReportHash, Revision: c.Revision}
}

// A syntactically valid forged proof reaches the missing-release-authority
// check. It never claims that processing completed fresh checks or a release.
func heldReleaseAttempt(t *testing.T, c *store.FileCheck) ReleaseDecision {
	t.Helper()
	if c == nil || c.State != "held" || c.Attempts != 0 || c.ReportHash != "" {
		t.Fatal("processing supplied checks or release authority")
	}
	d := releaseDecision(c)
	if !hashPattern.MatchString(d.SHA256) || !hashPattern.MatchString(d.PolicyHash) || d.Revision < 1 {
		t.Fatal("held check lost its exact file or policy binding")
	}
	d.ReportHash = secure.Digest([]byte("not a completed check report"))
	return d
}

func sameJSON(a, b []byte) bool {
	var left, right any
	x := json.NewDecoder(bytes.NewReader(a))
	x.UseNumber()
	y := json.NewDecoder(bytes.NewReader(b))
	y.UseNumber()
	return x.Decode(&left) == nil && y.Decode(&right) == nil && reflect.DeepEqual(left, right)
}
func TestHeldBytesNeedExactChecksAndSeparateAtomicRelease(t *testing.T) {
	f := setup(t)
	s, _, file := policyAndFile(t, f, goodCSV, true)
	c := getCheck(t, s, f, file.ID)
	if c.State != "held" {
		t.Fatal(c)
	}
	if _, _, err := f.wf.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("raw ID bypassed held state", err)
	}
	if _, err := f.wf.Custody.StatPath(f.ctx, f.scope, "/checked.csv"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("held file published", err)
	}
	replay, replayed, err := f.wf.Custody.AcceptAt(f.ctx, f.scope, "held", int64(len(goodCSV)), file.SHA256, strings.NewReader("do not consume replay"), custody.UploadTarget{Path: "/checked.csv"})
	if err != nil || !replayed || *replay != *file {
		t.Fatal(replay, replayed, err)
	}
	first, err := s.Run(f.ctx, f.scope, file.ID, "parse")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Run(f.ctx, f.scope, file.ID, "parse")
	if err != nil || !again.Replayed || !bytes.Equal(first.Resource, again.Resource) {
		t.Fatal(again, err)
	}
	c = getCheck(t, s, f, file.ID)
	if c.State != "passed" || c.Attempts != 1 {
		t.Fatal(c)
	}
	if _, _, err = f.wf.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("passing parse bypassed release approval", err)
	}
	wrong := releaseDecision(c)
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err = s.Release(f.ctx, f.scope, file.ID, "wrong", wrong); !errors.Is(err, store.ErrRevision) {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_check_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result->>'state'='released' THEN RAISE EXCEPTION 'task-owned release receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_test_check_receipt_failure BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_check_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c)); err == nil {
		t.Fatal("missing release receipt ignored")
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM file_releases)+(SELECT count(*) FROM namespace_entries WHERE kind='file')`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if getCheck(t, s, f, file.ID).State != "passed" {
		t.Fatal("partial release persisted")
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_check_receipt_failure ON check_receipts;DROP FUNCTION freightctl_test_check_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	released, err := s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c))
	if err != nil {
		t.Fatal(err)
	}
	again, err = s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c))
	if err != nil || !again.Replayed || !sameJSON(released.Resource, again.Resource) {
		t.Fatal(again, err)
	}
	_, data, err := f.wf.Custody.DownloadPath(f.ctx, f.scope, "/checked.csv")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(data)
	data.Close()
	if err != nil || string(body) != goodCSV {
		t.Fatal(err)
	}
	// A partner reader may read the approved path without seeing the actor-private
	// intake binding. Shared release proofs carry only the minimum gate metadata.
	token := filepath.Join(t.TempDir(), "reader.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.ProvisionPolicy(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token, []string{"read", "list"}, "/"); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	readerScope := f.scope
	readerScope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	_, reader, err := f.wf.Custody.OpenPathReader(f.ctx, readerScope, "/checked.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	p, err := s.Policy(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Revoke(f.ctx, f.scope, "revoke-read", PolicyDecision{Hash: p.Hash, Version: p.Version, Revision: p.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ReadAt(make([]byte, 1), 1); !errors.Is(err, store.ErrState) {
		t.Fatal("open reader ignored revoked policy", err)
	}
}

func TestEveryIngressHoldsAndDatabaseRefusesPublicationBypass(t *testing.T) {
	f := setup(t)
	s, _, file := policyAndFile(t, f, goodCSV, true)
	writer, err := s.Custody.OpenRevisionWriter(f.ctx, f.scope, "/sftp.csv", custody.WriteOptions{Create: true, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.WriteAt([]byte(goodCSV), 0); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	u, err := s.Custody.CreateUpload(f.ctx, f.scope, "ticket", custody.CreateUpload{Path: "/ticket.csv", Size: int64(len(goodCSV)), SHA256: secure.Digest([]byte(goodCSV))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Custody.AppendUpload(f.ctx, f.scope, u.Upload.ID, "chunk", 0, int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV)); err != nil {
		t.Fatal(err)
	}
	complete, err := s.Custody.CompleteUpload(f.ctx, f.scope, u.Upload.ID, "complete")
	if err != nil {
		t.Fatal(err)
	}
	if complete.Upload.State != "completed" || complete.File == nil || complete.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal(complete)
	}
	page, err := s.List(f.ctx, f.scope, "", 1)
	if err != nil || len(page.Checks) != 1 || page.Next == "" {
		t.Fatal(page, err)
	}
	more, err := s.List(f.ctx, f.scope, page.Next, 100)
	if err != nil || len(more.Checks) != 2 {
		t.Fatal(more, err)
	}
	all := append(page.Checks, more.Checks...)
	for _, summary := range all {
		if summary.State != "held" {
			t.Fatal(summary)
		}
		if _, err = s.Custody.StatPath(f.ctx, f.scope, summary.Path); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("ingress published held path", summary, err)
		}
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	tx.PendingFiles = map[string]bool{file.ID: true}
	if _, err = tx.ApplyPathCommand(f.ctx, "bypass", store.PathCommand{Operation: "publish", Path: "/bypass.csv", FileID: file.ID}, 1000); err == nil {
		t.Fatal("SQL allowed held-file publication")
	}
	_ = tx.Tx.Rollback(f.ctx)
	tx, err = s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &store.File{ID: secure.NewID(), Size: 3, SHA256: secure.Digest([]byte("abc")), Policy: "integrity-only-v1"}
	if err = tx.Accept(f.ctx, "bypass-policy", store.Meaning(3, legacy.SHA256), legacy); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err == nil {
		t.Fatal("SQL accepted new uncontrolled bytes under a configured policy")
	}
	for index, summary := range all {
		if _, err = s.Run(f.ctx, f.scope, summary.FileID, "parse-"+string(rune('a'+index))); err != nil {
			t.Fatal(err)
		}
		c := getCheck(t, s, f, summary.FileID)
		if _, err = s.Release(f.ctx, f.scope, summary.FileID, "release-"+string(rune('a'+index)), releaseDecision(c)); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Custody.StatPath(f.ctx, f.scope, summary.Path); err != nil {
			t.Fatal(err)
		}
	}
}
func TestRejectedCSVAndPrivateCheckRowsDoNotBecomeAvailable(t *testing.T) {
	f := setup(t)
	s, _, file := policyAndFile(t, f, "account,amount,day\nprivate-value,1e9,2026-10-28\n", true)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "parse"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	if c.State != "rejected" || bytes.Contains(c.Report, []byte("private-value")) {
		t.Fatal(c)
	}
	if _, _, err := f.wf.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal(err)
	}
	if _, err := s.Run(f.ctx, f.scope, file.ID, "again"); !errors.Is(err, store.ErrState) {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "other.token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := f.scope
	other.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	if _, err = s.Get(f.ctx, other, file.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	for _, table := range []string{"file_checks", "check_receipts"} {
		var n int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatal(table, n, err)
		}
	}
}
func TestChecksBindStorageCurrentPolicyAndUnchangedBytes(t *testing.T) {
	f := setup(t)
	s, p, file := policyAndFile(t, f, goodCSV, false)
	otherDisk, err := custody.Open(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer otherDisk.Close()
	wrong := &Service{Custody: &custody.Service{DB: s.Custody.DB, Disk: otherDisk}}
	if _, err = wrong.Run(f.ctx, f.scope, file.ID, "wrong-store"); !errors.Is(err, store.ErrState) {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, f.scope, file.ID, "parse"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	name := filepath.Join(f.diskPath, custody.Name(f.scope.Tenant, f.scope.Partner, file.ID))
	if err = os.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, bytes.Repeat([]byte("x"), len(goodCSV)), 0400); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(name, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "changed-bytes", releaseDecision(c)); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("changed bytes released", err)
	}
	if _, err = s.Register(f.ctx, f.scope, "rotate-policy", PolicyRequest{ExpectedVersion: p.Version, Definition: testPolicy(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "stale-policy", releaseDecision(c)); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale policy released", err)
	}
	if view, err := s.Get(f.ctx, f.scope, file.ID); err != nil || view.Current {
		t.Fatal(view, err)
	}
}
func TestCheckAttemptReplayAdmissionAndPolicyRevocationStayClosed(t *testing.T) {
	f := setup(t)
	s, p, file := policyAndFile(t, f, goodCSV, false)
	_, r1, err := s.Custody.DB.CheckSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, r2, err := s.Custody.DB.CheckSlot(f.ctx)
	if err != nil {
		r1()
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, f.scope, file.ID, "full"); !errors.Is(err, store.ErrLimit) {
		t.Fatal(err)
	}
	r2()
	r1()
	// Select one real durable worker attempt, then refuse a competing worker and
	// changes to that attempt's immutable source binding.
	c, _, _, a, _, err := s.start(f.ctx, f.scope, file.ID, "start")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err = s.start(f.ctx, f.scope, file.ID, "compete"); !errors.Is(err, store.ErrState) {
		t.Fatal(err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	forged := *c
	forged.Revision++
	forged.Binding = json.RawMessage(`{}`)
	if err = tx.SaveFileCheck(f.ctx, &forged, c.Revision); err == nil {
		t.Fatal("mutable source binding")
	}
	_ = tx.Tx.Rollback(f.ctx)
	if _, err = s.Revoke(f.ctx, f.scope, "revoke", PolicyDecision{Hash: p.Hash, Version: p.Version, Revision: p.Revision}); err != nil {
		t.Fatal(err)
	}
	if err = s.check(f.ctx, f.scope, a); !errors.Is(err, store.ErrRevision) {
		t.Fatal("revoked policy accepted by worker", err)
	}
	if _, _, err = s.Custody.Accept(f.ctx, f.scope, "after-revoke", 3, secure.Digest([]byte("abc")), strings.NewReader("abc")); !errors.Is(err, store.ErrState) {
		t.Fatal("revocation fell back to integrity-only", err)
	}
}
