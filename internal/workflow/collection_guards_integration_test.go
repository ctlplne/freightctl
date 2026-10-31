//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// These fixtures stage exact sealed bytes without a peer. Stock-peer and
// browser behavior is exercised independently by qualify-collections.py.
func sealedCollectionFixture(t *testing.T, f *fixture, x CollectionSelection, key string, bodies ...string) (*store.CollectionJob, string, []store.CollectionInput) {
	t.Helper()
	j, _ := startCollection(t, f, x, key)
	owner := secure.NewID()
	j, _, _, err := f.s.claimCollection(f.ctx, f.scope, j.ID, j.Hash, owner)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []CollectionFile{}}
	for i, body := range bodies {
		manifest.Files = append(manifest.Files, CollectionFile{Name: []string{"one.csv", "two.csv"}[i], Size: int64(len(body)), SHA256: secure.Digest([]byte(body))})
	}
	_, hash, _ := digest(manifest)
	if err = f.s.captureCollectionManifest(f.ctx, f.scope, j.ID, owner, j.Fence, manifest, hash); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	for i, input := range view.Inputs {
		if _, _, err = f.s.Custody.Disk.StageGenerated(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, input.ObjectID), input.Size, func(w io.Writer) error { _, e := io.WriteString(w, bodies[i]); return e }); err != nil {
			t.Fatal(err)
		}
	}
	return view.Job, owner, view.Inputs
}
func finishSealedCollection(t *testing.T, f *fixture, j *store.CollectionJob, owner string, inputs []store.CollectionInput) *CollectionView {
	t.Helper()
	for i := range inputs {
		if err := f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &inputs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.s.completeCollectionWork(f.ctx, f.scope, j.ID, owner, j.Fence, "finish-"+j.ID, secure.Digest([]byte(j.ID))); err != nil {
		t.Fatal(err)
	}
	v, err := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func collectionSQLRefusal(t *testing.T, err error) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		t.Fatal("expected journal, lineage or state constraint refusal", err)
	}
}

func TestCollectionAcceptanceAndCaptureReceiptsAreAtomicWithPaths(t *testing.T) {
	f, _, x := collectionFixture(t)
	j, owner, inputs := sealedCollectionFixture(t, f, x, "atomic-source", "account\n0001\n")
	input := inputs[0]
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_collection_accept_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_key LIKE 'collect-%' THEN RAISE EXCEPTION 'exact collection acceptance receipt fault' USING ERRCODE='P0001';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_collection_accept_fault BEFORE INSERT ON idempotency FOR EACH ROW EXECUTE FUNCTION freightctl_collection_accept_fault()`); err != nil {
		t.Fatal(err)
	}
	err := f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &input)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "P0001" {
		t.Fatal("did not reach original acceptance receipt boundary", err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files WHERE file_id=$1)+(SELECT count(*) FROM file_checks WHERE file_id=$1)+(SELECT count(*) FROM events WHERE resource_id=$1 AND kind='FileAccepted')+(SELECT count(*) FROM idempotency WHERE file_id=$1)`, input.ObjectID).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial file/intake/event/retry acceptance survived", count, err)
	}
	v, err := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil || v.Inputs[0].State != "pending" || v.Inputs[0].FileID != nil {
		t.Fatal(v, err)
	}
	sealed, err := f.s.Custody.Disk.VerifiedContext(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, input.ObjectID), input.Size, input.SHA256)
	if err != nil {
		t.Fatal("unconfirmed sealed object was destroyed", err)
	}
	sealed.Close()
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_collection_accept_fault ON idempotency;DROP FUNCTION freightctl_collection_accept_fault()`); err != nil {
		t.Fatal(err)
	}
	if err = f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &input); err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_collection_capture_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.request_key='atomic-capture' THEN RAISE EXCEPTION 'exact collection capture receipt fault' USING ERRCODE='P0001';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_collection_capture_fault BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_collection_capture_fault()`); err != nil {
		t.Fatal(err)
	}
	_, err = f.s.completeCollectionWork(f.ctx, f.scope, j.ID, owner, j.Fence, "atomic-capture", secure.Digest([]byte("atomic-capture")))
	if !errors.As(err, &pg) || pg.Code != "P0001" {
		t.Fatal("did not reach final capture receipt boundary", err)
	}
	v, err = f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil || v.Job.Captured || v.Job.State != "reading" || v.Inputs[0].State != "accepted" {
		t.Fatal("partial capture survived", v, err)
	}
	if _, err = f.s.Custody.StatPath(f.ctx, f.scope, input.Target); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("uncommitted capture published path", err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_collection_capture_fault ON workflow_receipts;DROP FUNCTION freightctl_collection_capture_fault()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.completeCollectionWork(f.ctx, f.scope, j.ID, owner, j.Fence, "atomic-capture", secure.Digest([]byte("atomic-capture"))); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil || !v.Job.Captured || v.LocalStates[0].State != "published" {
		t.Fatal("capture did not publish the exact input", v, err)
	}
}

func TestCollectionEachInputRequiresItsOwnIndependentDispatchApproval(t *testing.T) {
	f, _, x := collectionFixture(t)
	sender := &delivery.Service{Custody: f.s.Custody}
	if _, err := sender.ChangeDispatchPolicy(f.ctx, f.scope, "independent-policy", delivery.DispatchPolicyChange{Mode: "independent"}); err != nil {
		t.Fatal(err)
	}
	reviewer, account := approvalPeer(t, f, "Collection dispatch reviewer", []string{"inspect", "workflow_approve"})
	j, owner, inputs := sealedCollectionFixture(t, f, x, "held-source", "account\n0001\n", "account\n0002\n")
	v := finishSealedCollection(t, f, j, owner, inputs)
	if _, err := f.s.RefreshCollection(f.ctx, f.scope, j.ID, "queue-exact-inputs", Decision{Hash: j.Hash, Revision: v.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	v, err := f.s.CollectionStatus(f.ctx, f.scope, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range v.Inputs {
		if input.RunID == nil {
			t.Fatal("complete batch was not admitted")
		}
	}
	run, err := f.s.Status(f.ctx, f.scope, *v.Inputs[0].RunID)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := tx.Delivery(f.ctx, run.Steps[0].DeliveryID, false)
	tx.Tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = sender.Claim(f.ctx, f.scope, intent.ID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("collection bypassed independent dispatch approval", err)
	}
	_, review, _ := proposeDispatch(t, f, sender, intent, account.ID, "review-collected-input")
	if _, _, err = decideDispatch(t, f, sender, reviewer, review, "approve", "approve-collected-input"); err != nil {
		t.Fatal(err)
	}
	claimed, _, err := sender.Claim(f.ctx, f.scope, intent.ID, secure.NewID())
	if err != nil || claimed.Attempts != 1 {
		t.Fatal(claimed, err)
	}
	// Sending consent for the first exact file cannot authorize its sibling.
	second, err := f.s.Status(f.ctx, f.scope, *v.Inputs[1].RunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = sender.Claim(f.ctx, f.scope, second.Steps[0].DeliveryID, secure.NewID()); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("first input approval leaked to sibling", err)
	}
}

func TestCollectionPrivateHistoryAndRedactedAuditStayActorTenantPartnerScoped(t *testing.T) {
	f, _, x := collectionFixture(t)
	j, owner, inputs := sealedCollectionFixture(t, f, x, "private-source", "abc")
	finishSealedCollection(t, f, j, owner, inputs)
	peer, _ := approvalPeer(t, f, "Other collection manager", append([]string{}, store.DefaultPermissions...))
	scopes := []store.Scope{peer}
	for _, sameTenant := range []bool{true, false} {
		tenant := f.scope.Tenant
		if !sameTenant {
			tenant = secure.NewID()
		}
		partner := secure.NewID()
		token := filepath.Join(t.TempDir(), "separate-scope.token")
		if err := secure.WriteToken(token); err != nil {
			t.Fatal(err)
		}
		if err := store.Provision(f.ctx, f.adminPath, tenant, partner, token); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(token, 64)
		if err != nil {
			t.Fatal(err)
		}
		scopes = append(scopes, store.Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)})
		secret.Close()
	}
	for _, scope := range scopes {
		if _, err := f.s.CollectionStatus(f.ctx, scope, j.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("private collection disclosed", err)
		}
		page, err := f.s.Collections(f.ctx, scope, "", 100)
		if err != nil || len(page.Jobs) != 0 {
			t.Fatal(page, err)
		}
		tx, err := f.s.Custody.DB.Begin(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		var n int
		err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_collection_jobs)+(SELECT count(*) FROM workflow_collection_batches)+(SELECT count(*) FROM workflow_collection_inputs)`).Scan(&n)
		tx.Tx.Rollback(f.ctx)
		if err != nil || n != 0 {
			t.Fatal("RLS disclosed collection metadata", n, err)
		}
	}
	events, err := f.s.Custody.DB.Events(f.ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, event := range events {
		if event.Kind == "WorkflowCommandCompleted" && event.ResourceID != j.ID && event.ResourceID != j.WorkflowID {
			continue
		}
		if !strings.HasPrefix(event.Kind, "WorkflowCollection") && event.Kind != "WorkflowRevisionChanged" && event.Kind != "WorkflowCommandCompleted" {
			continue
		}
		seen++
		var redacted struct {
			Redacted bool
			Hash     string `json:"source_payload_sha256"`
		}
		if json.Unmarshal(event.Payload, &redacted) != nil || !redacted.Redacted || !hashPattern.MatchString(redacted.Hash) || bytes.Contains(event.Payload, []byte("one.csv")) || bytes.Contains(event.Payload, []byte(f.connection.Address)) {
			t.Fatal("ordinary audit disclosed private source", event.Kind, string(event.Payload))
		}
	}
	if seen < 8 {
		t.Fatal("missing collection/configuration receipt redaction", seen)
	}
}

func TestCollectionSQLCannotInventAcceptedInputCaptureOrUnprojectedEvent(t *testing.T) {
	f, _, x := collectionFixture(t)
	j, owner, inputs := sealedCollectionFixture(t, f, x, "sql-source", "abc")
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `UPDATE workflow_collection_jobs SET reason='invented',revision=revision+1 WHERE id=$1`, j.ID)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	tx, err = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	forged := *j
	forged.Revision++
	forged.State = "captured"
	forged.Captured = true
	forged.Owner = ""
	forged.Until = nil
	err = tx.SaveCollection(f.ctx, &forged, j.Revision)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	tx, err = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	input := inputs[0]
	input.Revision++
	input.State = "accepted"
	input.FileID = &input.ObjectID
	err = tx.SaveCollectionInput(f.ctx, &input, inputs[0].Revision)
	tx.Tx.Rollback(f.ctx)
	collectionSQLRefusal(t, err)
	tx, err = f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Append(f.ctx, "WorkflowCollectionInput", secure.NewID(), map[string]any{"approved": true})
	if err == nil {
		err = tx.Tx.Commit(f.ctx)
	} else {
		tx.Tx.Rollback(f.ctx)
	}
	collectionSQLRefusal(t, err)
	if err = f.s.acceptCollectionInput(f.ctx, f.scope, j.ID, owner, j.Fence, &inputs[0]); err != nil {
		t.Fatal("refused forgeries changed original legitimate input", err)
	}
}

func TestCollectionStatusRemainsReadableWhileCredentialWriterWaitsForGuard(t *testing.T) {
	f, _, x := collectionFixture(t)
	j, _ := startCollection(t, f, x, "guarded-source")
	_, account := approvalPeer(t, f, "Credential to rotate", []string{"inspect", "workflow_approve"})
	worker, err := f.s.collectionWorkerBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Tx.Rollback(context.Background())
	done := make(chan error, 1)
	finished := false
	defer func() {
		worker.Tx.Rollback(context.Background())
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("credential writer failed to finish")
			}
		}
	}()
	go func() {
		_, e := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-under-collection-guard", store.AccountCommand{Operation: "rotate", ID: account.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))})
		done <- e
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		err = f.admin.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='freightctl' AND l.locktype='advisory' AND NOT l.granted AND a.query LIKE 'INSERT INTO account_revisions%')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("credential writer did not reach actual collection guard")
		}
		time.Sleep(10 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	view, err := f.s.CollectionStatus(ctx, f.scope, j.ID)
	cancel()
	if err != nil || !view.Current {
		t.Fatal("read-only metadata blocked behind guarded credential mutation", view, err)
	}
	select {
	case e := <-done:
		finished = true
		t.Fatal("writer crossed active source guard", e)
	default:
	}
	worker.Tx.Rollback(f.ctx)
	select {
	case err = <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer remained blocked")
	}
}

func TestCollectionTargetHonorsGroupAncestorAndWriteModesWithoutDeliver(t *testing.T) {
	f := setup(t)
	parent := f.scope
	for _, p := range []string{"/permitted", "/permitted/target"} {
		groupMode := uint32(0770)
		if _, err := f.s.Custody.PathCommand(f.ctx, parent, "mkdir-"+strings.ReplaceAll(p, "/", "-"), store.PathCommand{Operation: "mkdir", Path: p, Mode: &groupMode}); err != nil {
			t.Fatal(err)
		}
	}
	child, account := approvalPeer(t, f, "Local collector", append([]string{}, store.DefaultPermissions...))
	result, err := f.s.RegisterConnection(f.ctx, child, "collector-connection", f.request)
	if err != nil {
		t.Fatal(err)
	}
	var conn ConnectionView
	if json.Unmarshal(result.Resource, &conn) != nil {
		t.Fatal("connection")
	}
	permissions := []string{}
	for _, p := range store.DefaultPermissions {
		if p != "admin" && p != "deliver" {
			permissions = append(permissions, p)
		}
	}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, parent, "remove-collector-admin-deliver", store.AccountCommand{Operation: "update", ID: account.ID, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Local collector", Root: "/", Permissions: permissions}}); err != nil {
		t.Fatal(err)
	}
	f.scope = child
	f.connection = conn
	source := collectionTestSource()
	source.Connection = Reference{ID: conn.ID, Version: conn.Version, Hash: conn.Hash}
	source.Directory = "/permitted/target"
	d := f.definition()
	d.Source = &source
	d.Steps = []Step{}
	w := f.approved(t, d)
	x := CollectionSelection{Workflow: Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}, Authority: 2, Timeout: 120}
	j, _ := startCollection(t, f, x, "nonadmin-local")
	mode := func(p string, m uint32) {
		t.Helper()
		entry, err := f.s.Custody.StatPath(f.ctx, parent, p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.Custody.PathCommand(f.ctx, parent, secure.NewID(), store.PathCommand{Operation: "setstat", Path: p, Mode: &m, ExpectedRevision: &entry.Revision}); err != nil {
			t.Fatal(err)
		}
	}
	for _, change := range []struct {
		path string
		deny uint32
	}{{"/permitted", 0700}, {"/permitted/target", 0550}} {
		mode(change.path, change.deny)
		v, err := f.s.CollectionStatus(f.ctx, child, j.ID)
		if err != nil || v.Current || v.Observed != "attention" {
			t.Fatal("SQL guard ignored current ancestor/write mode", v, err)
		}
		if _, err = f.s.PreviewCollection(f.ctx, child, x); !errors.Is(err, store.ErrForbidden) {
			t.Fatal("preview ignored current directory modes", err)
		}
		mode(change.path, 0770)
	}
	if _, err = f.s.CancelCollection(f.ctx, child, j.ID, "cancel-local-metadata", Decision{Hash: j.Hash, Revision: j.Revision}); err != nil {
		t.Fatal(err)
	}
	staged, owner, inputs := sealedCollectionFixture(t, f, x, "nonadmin-capture", "abc")
	v := finishSealedCollection(t, f, staged, owner, inputs)
	if len(v.Job.Definition) == 0 || v.Inputs[0].RunID != nil || v.LocalStates[0].State != "published" {
		t.Fatal("local-only collection required a dummy receiver", v)
	}
	d.Steps = f.definition().Steps[:1]
	forward := f.approved(t, d)
	x.Workflow = Reference{ID: forward.ID, Version: forward.Version, Hash: forward.Hash}
	if _, err = f.s.PreviewCollection(f.ctx, child, x); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("forwarding acquired missing deliver grant", err)
	}
}
