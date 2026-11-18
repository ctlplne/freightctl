//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
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
	stockOnwardWorkerDeath(t, nil)
}

type observeStockOnward func(*testing.T, *fixture, stockExchangeHTTPS, string, store.Scope, *OnwardReview, OnwardReconcileRequest) (OnwardReconciliation, string)

func stockOnwardWorkerDeath(t *testing.T, browser observeStockOnward) {
	t.Helper()
	binary := routingKeyCLI(t)
	f := setup(t)
	remote := newMixedStockReceiver(t, f)
	prepared := prepareStockOnward(t, f, remote)
	secretPath, actor, agent := prepared.token, prepared.actor, prepared.scope
	recovery, review := prepared.request, prepared.review
	start, runID, id := recovery.Start, recovery.RunID, recovery.DeliveryID
	db := f.s.Custody.DB
	body := []byte("abc")
	// Add a pause at the local success update for this one synthetic delivery.
	// The ordinary worker has already linked, verified and closed the final file.
	barrier := `CREATE FUNCTION freightctl_onward_success_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.delivery_id='` + id + `' AND NEW.state='succeeded' THEN PERFORM pg_sleep(8); END IF; RETURN NEW; END $$;
		CREATE TRIGGER freightctl_onward_success_pause BEFORE UPDATE ON delivery_intents FOR EACH ROW EXECUTE FUNCTION freightctl_onward_success_pause()`
	if _, err := f.admin.Exec(f.ctx, barrier); err != nil {
		t.Fatal(err)
	}
	drop := `DROP TRIGGER freightctl_onward_success_pause ON delivery_intents; DROP FUNCTION freightctl_onward_success_pause()`
	child := exec.CommandContext(f.ctx, binary, "workflow-work", "--dsn-file", f.runtimePath, "--storage", f.storagePath,
		"--token-file", secretPath, "--tenant", agent.Tenant, "--partner", agent.Partner, "--run-id", runID, "--idempotency-key", "original-onward-worker")
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	waitCollectionSQL(t, f, 12*time.Second, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep' AND query LIKE 'UPDATE delivery_intents%')`)
	final := filepath.Join(remote.directory, id+"-"+stockOnwardFilename)
	if wire, err := os.ReadFile(final); err != nil || !bytes.Equal(wire, body) || remote.sessions(t) != 1 {
		t.Fatal("the real stock receiver did not expose the exact final file before the worker lost its receipt", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	var exit *exec.ExitError
	if err := child.Wait(); !errors.As(err, &exit) {
		t.Fatal("original onward worker never died", err)
	}
	killed, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || killed.Signal() != syscall.SIGKILL || stdout.Len() != 0 {
		t.Fatal("original worker emitted a receipt or exited without SIGKILL")
	}
	if _, err := f.admin.Exec(f.ctx, drop); err != nil {
		t.Fatal(err)
	}
	sender := &delivery.Service{Custody: f.s.Custody}
	uncertain, err := sender.Status(f.ctx, agent, id)
	if err != nil || uncertain.State != "publishing" || uncertain.Fence != 1 || uncertain.Attempts != 1 || uncertain.LeaseUntil == nil {
		t.Fatal("worker death lost the durable publication boundary", err)
	}
	client := collectedExchangeStockClient(t, f, binary)
	agentHTTP := client.curl(secretPath)
	const recoveryRoute = "/onward/reconcile"
	agentHTTP(recoveryRoute, "live-lease", recovery, 409)
	if remote.sessions(t) != 1 {
		t.Fatal("observation contacted a receiver while the original lease was live")
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
	client.curl(f.tokenPath)(recoveryRoute, "different-actor", recovery, 404)
	wrong := recovery
	wrong.RunID = secure.NewID()
	agentHTTP(recoveryRoute, "different-run", wrong, 409)
	wrong = recovery
	wrong.DeliveryID = secure.NewID()
	agentHTTP(recoveryRoute, "unrelated-intent", wrong, 404)
	wrong = recovery
	wrong.Start.ReviewHash = secure.Digest([]byte("unrelated review"))
	agentHTTP(recoveryRoute, "different-review", wrong, 409)
	func() {
		for range 2 {
			_, release, err := db.DeliveryWorkerSlot(f.ctx)
			if err != nil {
				t.Fatal("retain exact test stream capacity", err)
			}
			defer release()
		}
		agentHTTP(recoveryRoute, "capacity-saturated", recovery, 413)
	}()
	if remote.sessions(t) != 1 {
		t.Fatal("refused recovery contacted the registered receiver")
	}
	// A receiver can move a file as part of processing. An absent name therefore
	// leaves an ambiguous observation even though this worker really published it.
	moved := final + ".fixture-moved"
	if err = os.Rename(final, moved); err != nil {
		t.Fatal(err)
	}
	const missingKey = "observe-unconfirmed-final-name"
	missing := readStockExchangeJSON[OnwardReconciliation](t, agentHTTP(recoveryRoute, missingKey, recovery, 200))
	if missing.Replayed || missing.RunID != runID || missing.DeliveryID != id || missing.DeliveryState != "ambiguous" || missing.Observation != "unconfirmed" || remote.sessions(t) != 2 {
		t.Fatal("missing receiver file did not retain uncertainty")
	}
	if err = os.Rename(moved, final); err != nil {
		t.Fatal(err)
	}
	original, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	missingReplay := readStockExchangeJSON[OnwardReconciliation](t, agentHTTP(recoveryRoute, missingKey, recovery, 200))
	missing.Replayed = true
	if missingReplay != missing || remote.sessions(t) != 2 {
		t.Fatalf("original missing-file result changed: observation=%s/%s hash=%s/%s replayed=%t contacts=%d", missing.Observation, missingReplay.Observation, missing.ObservationSHA256, missingReplay.ObservationSHA256, missingReplay.Replayed, remote.sessions(t))
	}
	wire, err := json.Marshal(recovery)
	var args map[string]any
	if err != nil || json.Unmarshal(wire, &args) != nil {
		t.Fatal("encode exact reviewed recovery", err)
	}
	tools := client.tools(t, f.ctx, secretPath)
	matchedKey := "observe-matching-final-bytes"
	var match OnwardReconciliation
	if browser == nil {
		args["request_key"] = matchedKey
		match = readStockExchangeJSON[OnwardReconciliation](t, tools("reconcile_onward", args, ""))
	} else {
		match, matchedKey = browser(t, f, client, secretPath, agent, review, recovery)
	}
	if match.Replayed || match.RunID != runID || match.DeliveryID != id || match.DeliveryState != "succeeded" || match.Observation != "integrity-observed" ||
		match.ReceiverPersistence != "unknown" || match.BusinessProcessing != "unknown" || remote.sessions(t) != 3 {
		t.Fatal("exact readback did not resolve only the bound integrity outcome")
	}
	status, err := sender.Status(f.ctx, agent, id)
	if err != nil || status.Fence != 1 || status.Attempts != 1 || status.LeaseUntil != nil {
		t.Fatal("readback advanced the sending fence or lost the receipt binding", err)
	}
	hash, err := onwardObservationHash(status.Observation)
	if err != nil || hash != match.ObservationSHA256 {
		t.Fatal("recorded readback digest differs from the API observation", err)
	}
	var observed struct {
		SHA256 string `json:"sha256"`
		Fsync  bool   `json:"file_fsync_acknowledged"`
	}
	if json.Unmarshal(status.Observation, &observed) != nil || observed.SHA256 != start.Request.Artifact.SHA256 || observed.Fsync {
		t.Fatal("read-only reconciliation claimed a file sync or changed the wire digest")
	}
	finish, err := f.s.Status(f.ctx, agent, runID)
	if err != nil || finish.Run.State != "succeeded" || finish.ObservedState != "succeeded" {
		t.Fatal("reconciled observation and run projection did not commit together", err)
	}
	after, err := os.Stat(final)
	if err != nil || !os.SameFile(original, after) || after.ModTime() != original.ModTime() || after.Mode() != original.Mode() {
		t.Fatal("remote readback altered the original published inode", err)
	}
	entries, err := os.ReadDir(remote.directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(final) {
		t.Fatal("remote readback created or retained an unexpected file", err)
	}
	match.Replayed = true
	if actual := readStockExchangeJSON[OnwardReconciliation](t, agentHTTP(recoveryRoute, matchedKey, recovery, 200)); actual != match {
		t.Fatal("stock HTTPS did not recover the original observation")
	}
	args["request_key"] = matchedKey
	if actual := readStockExchangeJSON[OnwardReconciliation](t, tools("reconcile_onward", args, "")); actual != match {
		t.Fatal("MCP did not recover the original observation")
	}
	requestFile := filepath.Join(t.TempDir(), "reviewed-observation.json")
	if err = os.WriteFile(requestFile, wire, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(f.ctx, binary, "onward-reconcile", "--dsn-file", f.runtimePath, "--storage", f.storagePath,
		"--token-file", secretPath, "--tenant", agent.Tenant, "--partner", agent.Partner, "--request-file", requestFile, "--idempotency-key", matchedKey).Output()
	if err != nil || readStockExchangeJSON[OnwardReconciliation](t, output) != match || remote.sessions(t) != 3 {
		t.Fatal("CLI did not recover the original observation without receiver contact", err)
	}
	const otherKey = "other-reviewed-onward-start"
	other, err := f.s.StartOnward(f.ctx, agent, otherKey, start)
	if err != nil {
		t.Fatal("reviewed comparison run", err)
	}
	otherRun := readStockExchangeJSON[OnwardRunReceipt](t, other.Resource)
	otherView, err := f.s.Status(f.ctx, agent, otherRun.ID)
	if err != nil || len(otherView.Steps) != 1 {
		t.Fatal("reviewed comparison step", err)
	}
	wrong = recovery
	wrong.ReceiptKey, wrong.RunID, wrong.DeliveryID = otherKey, otherRun.ID, otherView.Steps[0].DeliveryID
	conflict := readStockExchangeJSON[map[string]string](t, agentHTTP(recoveryRoute, matchedKey, wrong, 409))
	if conflict["error"] != "idempotency_conflict" || remote.sessions(t) != 3 {
		t.Fatal("observation key was adopted by a different valid reviewed intent")
	}
	var receipts, missedEvents int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM delivery_receipts WHERE actor_id=$1 AND delivery_id=$2),(SELECT count(*) FROM events WHERE actor_id=$1 AND resource_id=$2 AND kind='DeliveryReconciliationObserved')`, actor, id).Scan(&receipts, &missedEvents); err != nil || receipts != 2 || missedEvents != 1 {
		t.Fatal("observation replays duplicated or lost durable evidence", err)
	}
	remote.requireBytes(t, f, id+"-"+stockOnwardFilename)
	t.Log("stock SFTP worker died after publication; original lease expired; missing and matching observations recorded; cross-surface replays kept one attempt and fence")
}

const stockOnwardFilename = "onward.csv"

type preparedStockOnward struct {
	token   string
	actor   string
	scope   store.Scope
	review  *OnwardReview
	request OnwardReconcileRequest
}

func prepareStockOnward(t *testing.T, f *fixture, remote *mixedStockReceiver) preparedStockOnward {
	t.Helper()
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
		ID: "send", Kind: "sftp.deliver", Connection: route, Filename: stockOnwardFilename,
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
	receiptKey := secure.NewID()
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
	return preparedStockOnward{token: secretPath, actor: actor, scope: agent, review: review, request: OnwardReconcileRequest{OnwardLookup: OnwardLookup{Start: start, ReceiptKey: receiptKey}, RunID: run.ID, DeliveryID: id}}
}
