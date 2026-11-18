//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// The sender owns the run and its file under ordinary onward permissions.
// An actual worker dies after the independent receiver exposes the final file.
func TestStockSFTPOnwardWorkerDeathKeepsExactActorBoundary(t *testing.T) {
	binary := routingKeyCLI(t)
	f := setup(t)
	remote := newMixedStockReceiver(t, f)
	secretPath := filepath.Join(t.TempDir(), "agent.token")
	if err := secure.WriteToken(secretPath); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(secretPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	proof := secure.Digest(secret.Bytes)
	secret.Close()
	actor := secure.NewID()
	account := store.AccountCommand{Operation: "create", ID: actor, CredentialHash: proof,
		Policy: &store.AccountPolicy{Label: "Onward agent", Root: "/", Permissions: []string{"read", "list", "write", "deliver", "workflow_manage", "workflow_approve", "workflow_execute"}}}
	db := f.s.Custody.DB
	if _, err = db.ChangeAccount(f.ctx, f.scope, "stock-recovery-agent", account); err != nil {
		t.Fatal(err)
	}
	agent := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: proof}
	source := Reference{ID: remote.connection.ID, Version: remote.connection.Version, Hash: remote.connection.Hash}
	assigned, err := f.s.ProvisionConnection(f.ctx, f.scope, "stock-recovery-route", ConnectionProvisionCommand{
		Operation: "provision", Source: &source, Recipient: actor, RecipientAuthority: 1,
	})
	if err != nil {
		t.Fatal("separate operator SFTP assignment", err)
	}
	route := readStockExchangeJSON[ConnectionProvisionReceipt](t, assigned.Resource).Connection
	delegate := *f
	delegate.scope = agent
	approved := delegate.approved(t, Definition{Schema: 1, Name: "Reviewed onward worker recovery", Steps: []Step{{
		ID: "send", Kind: "sftp.deliver", Connection: route, Filename: "onward.csv",
	}}})
	body := []byte("abc")
	file, _, err := f.s.Custody.AcceptAt(f.ctx, agent, "agent-recovery-revision", int64(len(body)), secure.Digest(body), bytes.NewReader(body), custody.UploadTarget{Path: "/agent-onward.csv"})
	if err != nil {
		t.Fatal("agent-owned exact revision", err)
	}
	request := OnwardRequest{Schema: 1, Profile: OnwardProfile, Workflow: Reference{ID: approved.ID, Version: approved.Version, Hash: approved.Hash},
		Artifact: store.ExchangeArtifact{ID: file.ID, Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}}
	review, err := f.s.PrepareOnward(f.ctx, agent, request)
	if err != nil || remote.sessions(t) != 0 {
		t.Fatal("onward review contacted receiver or failed", err)
	}
	start := OnwardStart{Request: request, ReviewHash: review.ReviewHash}
	const receiptKey = "original-stock-onward-start"
	acceptance, err := f.s.StartOnward(f.ctx, agent, receiptKey, start)
	if err != nil {
		t.Fatal("exact onward queue", err)
	}
	run := readStockExchangeJSON[OnwardRunReceipt](t, acceptance.Resource)
	view, err := f.s.Status(f.ctx, agent, run.ID)
	if err != nil || len(view.Steps) != 1 || view.Steps[0].State != "queued" || remote.sessions(t) != 0 {
		t.Fatal("onward queue changed the number of pending steps or reached the receiver", err)
	}
	id := view.Steps[0].DeliveryID
	if !store.ValidID(id) {
		t.Fatal("the approved step lacks an exact intent identity")
	}
	// Add a pause at the local success update for this one synthetic delivery.
	// The ordinary worker has already linked, verified and closed the final file.
	barrier := `CREATE FUNCTION freightctl_onward_success_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='` + id + `' AND NEW.state='succeeded' THEN PERFORM pg_sleep(8); END IF; RETURN NEW; END $$;
		CREATE TRIGGER freightctl_onward_success_pause BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_onward_success_pause()`
	if _, err = f.admin.Exec(f.ctx, barrier); err != nil {
		t.Fatal(err)
	}
	drop := `DROP TRIGGER freightctl_onward_success_pause ON delivery_intents; DROP FUNCTION freightctl_onward_success_pause()`
	child := exec.CommandContext(f.ctx, binary, "workflow-work", "--dsn-file", f.runtimePath, "--storage", f.storagePath,
		"--token-file", secretPath, "--tenant", agent.Tenant, "--partner", agent.Partner, "--run-id", run.ID, "--idempotency-key", "original-onward-worker")
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	waitCollectionSQL(t, f, 12*time.Second, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep' AND query LIKE 'UPDATE delivery_intents%')`)
	final := filepath.Join(remote.directory, id+"-onward.csv")
	if wire, err := os.ReadFile(final); err != nil || !bytes.Equal(wire, body) || remote.sessions(t) != 1 {
		t.Fatal("the real stock receiver did not expose the exact final file before the worker lost its receipt", err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err = child.Wait(); !errors.As(err, &exit) {
		t.Fatal("original onward worker never died", err)
	}
	killed, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || killed.Signal() != syscall.SIGKILL || stdout.Len() != 0 {
		t.Fatal("original worker emitted a receipt or exited without SIGKILL")
	}
	if _, err = f.admin.Exec(f.ctx, drop); err != nil {
		t.Fatal(err)
	}
	sender := &delivery.Service{Custody: f.s.Custody}
	uncertain, err := sender.Status(f.ctx, agent, id)
	if err != nil || uncertain.State != "publishing" || uncertain.Fence != 1 || uncertain.Attempts != 1 || uncertain.LeaseUntil == nil {
		t.Fatal("worker death lost the durable publication boundary", err)
	}
	waitCollectionSQL(t, f, 35*time.Second, `SELECT clock_timestamp()>=lease_until FROM delivery_intents WHERE delivery_id=$1`, id)
	if _, err = sender.Reconcile(f.ctx, agent, id); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("the operator-only command did not preserve its management boundary", err)
	}
	if _, err = sender.Reconcile(f.ctx, f.scope, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("an operator could reach another actor's private onward intent", err)
	}
	if remote.sessions(t) != 1 {
		t.Fatal("a refused recovery contacted the receiver")
	}
	still, err := sender.Status(f.ctx, agent, id)
	if err != nil || still.State != uncertain.State || still.Revision != uncertain.Revision || still.Fence != uncertain.Fence || still.Attempts != uncertain.Attempts || still.LeaseUntil == nil || !still.LeaseUntil.Equal(*uncertain.LeaseUntil) {
		t.Fatal("refused recovery changed the original durable state", err)
	}
	remote.requireBytes(t, &delegate, id+"-onward.csv")
	t.Log("stock SFTP worker died after publication; original lease expired; least-privilege agent and unrelated operator both refused; independent bytes unchanged")
}
