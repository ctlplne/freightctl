//go:build integration && exchangebrowser && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestStockSFTPCollectedArtifactBrowserToOwnedCopyAndStockSFTP(t *testing.T) {
	binary := routingKeyCLI(t)
	f := setup(t)
	producer := newStockSFTPPeer(t, f, true)
	receiver := newMixedStockReceiver(t, f)
	collection, selection := prepareCollectionTest(t, f, producer.connection, false, false)
	body := []byte("abc")
	_, originals := publishStockSFTPCollection(t, producer.directory, collection.Manifest, body)
	f.s.Custody.Exchanges = custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 16, MaxEndpoints: 16}
	client := collectedExchangeStockClient(t, f, binary)
	sender := client.curl(f.tokenPath)
	queued := captureCollectionOverHTTPS(t, sender, selection, func() int64 { return int64(producer.sessions(t)) })
	captured := requireCollectedBytes(t, f, queued.ID, body)
	input := captured.Inputs[0]
	entry, err := f.s.Custody.StatPath(f.ctx, f.scope, input.Target)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0600)
	if _, err = f.s.Custody.PathCommand(f.ctx, f.scope, "browser-source-owner-only", store.PathCommand{
		Operation: "setstat", Path: input.Target, Mode: &mode, ExpectedRevision: &entry.Revision,
	}); err != nil {
		t.Fatal(err)
	}

	db := f.s.Custody.DB
	private, err := os.MkdirTemp("../../.private", "freightctl-browser-stock-sftp-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(private); err != nil {
				t.Error(err)
			}
		}
	})
	token := filepath.Join(private, "participant.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	proof := secure.Digest(secret.Bytes)
	secret.Close()
	recipient := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: proof}
	actor := secure.NewID()
	policy := store.AccountPolicy{Label: "Receiving account", Root: "/", Permissions: []string{"read", "list", "write"}}
	if _, err = db.ChangeAccount(f.ctx, f.scope, "enroll-browser-recipient", store.AccountCommand{Operation: "create", ID: actor, CredentialHash: proof, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	// The owner supplies a separate execution grant before enrolling the pinned
	// receive endpoint. Receiving the file cannot grant those permissions.
	policy.Permissions = append(slices.Clone(policy.Permissions), "deliver", "workflow_manage", "workflow_approve", "workflow_execute")
	if _, err = db.ChangeAccount(f.ctx, f.scope, "grant-browser-onward-authority", store.AccountCommand{Operation: "update", ID: actor, ExpectedRevision: 1, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	participant := func(scope store.Scope) store.ExchangeParticipant {
		id, err := db.Identity(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: id.Actor, AuthorityRevision: id.AuthorityRevision, RootPolicyDigest: id.RootPolicyDigest}
	}
	owner, agent := participant(f.scope), participant(recipient)
	command := store.ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
		Schema: 1, Profile: "custody-https-poll-v1", Recipient: agent, Senders: []store.ExchangeParticipant{owner},
	}}
	endpoint := readStockExchangeJSON[store.ExchangeEndpointResult](t, sender("/exchange-endpoints/commands", "register-browser-receive-endpoint", command, 200))
	exactRoute, _ := provisionStockRoute(t, f, binary, sender, client.curl(token), recipient, actor, receiver)
	delegate := *f
	delegate.scope = recipient
	approved := delegate.approved(t, Definition{Schema: 1, Name: "Approved browser onward exchange", Steps: []Step{{
		ID: "send", Kind: "sftp.deliver", Connection: exactRoute.Connection, Filename: "agent-owned.csv",
	}}})
	if receiver.sessions(t) != 0 {
		t.Fatal("endpoint enrollment, route assignment or workflow approval contacted the receiver")
	}

	pemBytes, err := os.ReadFile(client.certificate)
	cert, _ := pem.Decode(pemBytes)
	if err != nil || cert == nil || cert.Type != "CERTIFICATE" {
		t.Fatal("task HTTPS certificate unavailable", err)
	}
	configFile, resultFile := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	value, err := json.Marshal(map[string]any{
		"prefix": client.prefix, "certificate_der": cert.Bytes, "tenant": f.scope.Tenant, "partner": f.scope.Partner,
		"sender": f.tokenPath, "recipient": token, "sender_actor": owner.Actor, "recipient_actor": agent.Actor,
		"collection": queued.ID, "input": input.ID, "source_name": input.Name, "source_file": input.ObjectID,
		"source_sha256": input.SHA256, "source_size": input.Size, "manifest": *captured.Job.ManifestHash, "endpoint": endpoint.Endpoint.ID,
		"workflow": Reference{ID: approved.ID, Version: approved.Version, Hash: approved.Hash}, "connection": exactRoute.Connection,
		"receiver_log": receiver.log, "download": filepath.Join(private, "received.bin"), "result": resultFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configFile, value, 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(f.ctx, "node", "../../scripts/stock-sftp-exchange-browser.mjs", configFile)
	child.Cancel = func() error { return child.Process.Signal(os.Interrupt) }
	child.WaitDelay = 5 * time.Second
	output, runErr := child.CombinedOutput()
	if err = os.WriteFile(filepath.Join(private, "browser.log"), output, 0600); err != nil {
		t.Fatal(err)
	}
	var result struct {
		State         string `json:"state"`
		Phase         string `json:"phase"`
		Browser       string `json:"browser_version"`
		Sandbox       bool   `json:"browser_sandbox"`
		Egress        int    `json:"external_egress"`
		RuntimeErrors int    `json:"runtime_errors"`
		Accessibility int    `json:"accessibility_checks"`
		Requests      int    `json:"work_requests"`
		Offer         string `json:"offer"`
		Copy          string `json:"copy"`
		Run           string `json:"run"`
		Delivery      string `json:"delivery"`
	}
	wire, err := os.ReadFile(resultFile)
	if err != nil || json.Unmarshal(wire, &result) != nil || runErr != nil || result.Phase != "complete" || result.State != "passed" ||
		!result.Sandbox || result.Egress != 0 || result.RuntimeErrors != 0 || result.Accessibility != 5 || result.Requests != 2 ||
		!store.ValidID(result.Offer) || !store.ValidID(result.Copy) || !store.ValidID(result.Run) || !store.ValidID(result.Delivery) {
		t.Fatalf("browser stock exchange failed; phase=%q; output_sha256=%s; private_fixture=%s; error=%v", result.Phase, secure.Digest(output), filepath.Base(private), runErr)
	}
	status, err := (&delivery.Service{Custody: f.s.Custody}).Status(f.ctx, recipient, result.Delivery)
	var observation struct {
		SHA256 string `json:"sha256"`
		Fsync  bool   `json:"file_fsync_acknowledged"`
	}
	if err != nil || status.FileID != result.Copy || status.Attempts != 1 || status.Fence != 1 ||
		json.Unmarshal(status.Observation, &observation) != nil || observation.SHA256 != input.SHA256 || !observation.Fsync || receiver.sessions(t) != 1 {
		t.Fatal("browser retry changed the transfer, exact copy or durable witness", err)
	}
	var offers, copies, runs, intents int
	if err = f.admin.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM artifact_exchanges WHERE sender_actor_id=$1 AND exchange_id=$3),
		(SELECT count(*) FROM events WHERE actor_id=$2 AND kind='FileAccepted' AND resource_id=$4 AND payload->'exchange_copy'->>'exchange_id'=$3::uuid::text),
		(SELECT count(*) FROM workflow_runs WHERE actor_id=$2 AND run_id=$5),
		(SELECT count(*) FROM workflow_steps WHERE actor_id=$2 AND run_id=$5 AND delivery_id=$6)`, owner.Actor, agent.Actor,
		result.Offer, result.Copy, result.Run, result.Delivery).Scan(&offers, &copies, &runs, &intents); err != nil || offers != 1 || copies != 1 || runs != 1 || intents != 1 {
		t.Fatal("browser changed the exact custody or onward journal binding", err)
	}
	receiver.requireBytes(t, &delegate, result.Delivery+"-agent-owned.csv")
	for name, before := range originals {
		after, err := os.ReadFile(filepath.Join(producer.directory, name))
		if err != nil || !bytes.Equal(after, before) {
			t.Fatal("browser exchange changed original producer bytes", err)
		}
	}
	if producer.sessions(t) != 1 {
		t.Fatal("browser offer, readback or onward retry reconnected to the producer")
	}
	t.Logf("stock browser exchange passed; browser=%s; work_requests=%d; delivery_attempts=%d; accessibility=%d; egress=%d", result.Browser, result.Requests, status.Attempts, result.Accessibility, result.Egress)
}
