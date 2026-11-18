//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func provisionStockRoute(t *testing.T, f *fixture, binary string, operatorHTTP, agentHTTP stockExchangeRequest, agent store.Scope, actor string, stock *mixedStockReceiver) (ConnectionProvisionReceipt, func(string, ConnectionProvisionCommand) (ConnectionProvisionReceipt, Result)) {
	t.Helper()
	db := f.s.Custody.DB
	original, err := db.Identity(f.ctx, agent)
	if err != nil || original.Actor != actor || original.AuthorityRevision <= 1 || slices.Contains(original.Permissions, "admin") || slices.Contains(original.Permissions, "connections_manage") {
		t.Fatal("agent provisioning fixture already has management authority", err)
	}
	source := Reference{ID: stock.connection.ID, Version: stock.connection.Version, Hash: stock.connection.Hash}
	command := ConnectionProvisionCommand{Operation: "provision", Recipient: actor, RecipientAuthority: original.AuthorityRevision, Source: &source}
	const route = "/connections/provisioning/commands"
	agentHTTP(route, "recipient-cannot-provision", command, 403)
	stale := command
	stale.RecipientAuthority--
	refused := readStockExchangeJSON[map[string]string](t, operatorHTTP(route, "stale-recipient-provision", stale, 409))
	if refused["error"] != "revision_conflict" {
		t.Fatal("operator provision lost the stale recipient refusal")
	}
	foreign := store.Scope{Tenant: f.scope.Tenant, Partner: secure.NewID()}
	foreignToken := filepath.Join(t.TempDir(), "other-partner.token")
	if err = secure.WriteToken(foreignToken); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, foreign.Tenant, foreign.Partner, foreignToken); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(foreignToken, 64)
	if err != nil {
		t.Fatal(err)
	}
	foreign.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	other, err := db.Identity(f.ctx, foreign)
	if err != nil {
		t.Fatal(err)
	}
	outside := command
	outside.Recipient, outside.RecipientAuthority = other.Actor, other.AuthorityRevision
	operatorHTTP(route, "foreign-recipient-provision", outside, 404)
	control := func(key string, cmd ConnectionProvisionCommand) (ConnectionProvisionReceipt, Result) {
		t.Helper()
		raw := operatorHTTP(route, key, cmd, 200)
		result := readStockExchangeJSON[Result](t, raw)
		provision := readStockExchangeJSON[ConnectionProvisionReceipt](t, result.Resource)
		if provision.Profile != operatorConnectionProfile || bytes.Contains(raw, []byte(stock.client)) {
			t.Fatal("operator HTTPS provision changed its profile or disclosed a private reference")
		}
		return provision, result
	}
	cli := func(key string, cmd ConnectionProvisionCommand) (ConnectionProvisionReceipt, Result) {
		t.Helper()
		raw, err := json.Marshal(cmd)
		if err != nil {
			t.Fatal(err)
		}
		request := filepath.Join(t.TempDir(), "provision.json")
		if err = os.WriteFile(request, raw, 0600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(f.ctx, binary, "connection-provision", "--dsn-file", f.runtimePath, "--token-file", f.tokenPath,
			"--tenant", f.scope.Tenant, "--partner", f.scope.Partner, "--request-file", request, "--idempotency-key", key).CombinedOutput()
		var result Result
		var provision ConnectionProvisionReceipt
		if err != nil || json.Unmarshal(output, &result) != nil || json.Unmarshal(result.Resource, &provision) != nil ||
			provision.Profile != operatorConnectionProfile || bytes.Contains(output, []byte(stock.client)) {
			t.Fatalf("operator CLI provision failed or disclosed private references; output_sha256=%s; error=%v", secure.Digest(output), err)
		}
		return provision, result
	}
	first, firstResult := control("provision-agent-route", command)
	manager, err := db.Identity(f.ctx, f.scope)
	if err != nil || firstResult.Replayed || first.Operator != manager.Actor || first.Recipient != actor || first.RecipientAuthority != original.AuthorityRevision ||
		first.Connection.ID == source.ID || first.Connection.Hash != source.Hash || first.Connection.Version != 1 || first.State != "active" || stock.sessions(t) != 0 {
		t.Fatal("provision changed identity, authority or approved destination", err)
	}
	requireProvisionProjectionGuards(t, f, agent, first)
	cliReplay, saved := cli("provision-agent-route", command)
	replayed, httpSaved := control("provision-agent-route", command)
	if !saved.Replayed || !httpSaved.Replayed || cliReplay != first || replayed != first {
		t.Fatal("CLI or HTTPS provision retry changed the registration or journal event")
	}
	conflict := readStockExchangeJSON[map[string]string](t, operatorHTTP(route, "provision-agent-route", stale, 409))
	if conflict["error"] != "idempotency_conflict" {
		t.Fatal("connection provisioning key was rebound")
	}
	var recordedBy, owner string
	err = f.admin.QueryRow(f.ctx, `SELECT e.actor_id::text,c.actor_id::text FROM events e JOIN connection_revisions c
		ON (c.tenant_id,c.partner_id,c.changed_event_id)=(e.tenant_id,e.partner_id,e.event_id)
		WHERE e.tenant_id=$1 AND e.partner_id=$2 AND e.event_id=$3 AND e.kind='OperatorConnectionChanged' AND c.connection_id=$4`,
		f.scope.Tenant, f.scope.Partner, first.EventID, first.Connection.ID).Scan(&recordedBy, &owner)
	if err != nil || recordedBy != manager.Actor || owner != actor {
		t.Fatal("projection impersonated the agent or lost its operator event", err)
	}
	agentHTTP("/connections/"+source.ID+"/"+strconv.Itoa(source.Version), "", nil, 404)
	assignedRoute := "/connections/" + first.Connection.ID + "/1"
	operatorHTTP(assignedRoute, "", nil, 404)
	view := readStockExchangeJSON[ConnectionView](t, agentHTTP(assignedRoute, "", nil, 200))
	if view.ID != first.Connection.ID || view.State != "active" || view.Hash != source.Hash || view.HostFingerprint != stock.connection.HostFingerprint || view.KeyFingerprint != stock.connection.KeyFingerprint || view.Directory != stock.connection.Directory {
		t.Fatal("recipient connection did not preserve exact pins")
	}
	return first, control
}

func requireProvisionProjectionGuards(t *testing.T, f *fixture, recipient store.Scope, recorded ConnectionProvisionReceipt) {
	t.Helper()
	db := f.s.Custody.DB
	for _, scope := range []store.Scope{recipient, f.scope} {
		tx, err := db.Begin(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		candidate := recorded
		candidate.Operator, candidate.OperatorAuthority = tx.Actor, tx.AuthorityRevision
		if scope == recipient {
			candidate.Recipient, candidate.RecipientAuthority = recorded.Operator, recorded.OperatorAuthority
		}
		candidate.Connection.ID, candidate.EventID = secure.NewID(), ""
		key, meaning := "unauthorized-projection", secure.Digest([]byte(candidate.Connection.ID))
		candidate.EventID, err = tx.Append(f.ctx, "OperatorConnectionChanged", candidate.Connection.ID, map[string]any{
			"request_key": key, "request_hash": meaning, "provision": candidate,
		})
		if err != nil {
			tx.Tx.Rollback(f.ctx)
			t.Fatal(err)
		}
		if scope == recipient {
			err = tx.WorkflowReceipt(f.ctx, key, meaning, candidate.Connection.ID, candidate)
			tx.Tx.Rollback(f.ctx)
			if !errors.Is(provisionError(err), store.ErrForbidden) {
				t.Fatal("an exact journal and receipt bypassed operator authority", err)
			}
		} else if err = tx.Tx.Commit(f.ctx); !errors.Is(provisionError(err), store.ErrIsolation) {
			t.Fatal("standalone provisioning event committed without a receipt", err)
		}
		var count int
		if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE event_id=$1`, candidate.EventID).Scan(&count); err != nil || count != 0 {
			t.Fatal("rejected connection operation persisted a journal row", err)
		}
	}
}
