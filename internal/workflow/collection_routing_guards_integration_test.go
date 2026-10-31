//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestCapturedRoutingPrivateRecordsReceiptsAndAuditRemainActorTenantPartnerScoped(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "private-routing-propose")
	a = decideRoutingAuthorization(t, f, a, "approve", "private-routing-approve")
	peer, _ := approvalPeer(t, f, "Other routing operator", append([]string{}, store.DefaultPermissions...))
	scopes := []store.Scope{peer}
	for _, sameTenant := range []bool{true, false} {
		tenant := f.scope.Tenant
		if !sameTenant {
			tenant = secure.NewID()
		}
		partner, token := secure.NewID(), filepath.Join(t.TempDir(), "foreign.token")
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
		if _, err := f.s.CollectionRoutingStatus(f.ctx, scope, a.JobID, a.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("private routing status disclosed", err)
		}
		if _, err := f.s.CollectionRoutingHistory(f.ctx, scope, a.JobID, 0, 20); !errors.Is(err, store.ErrNotFound) {
			t.Fatal("private routing history disclosed", err)
		}
		tx, err := f.s.Custody.DB.Begin(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		var bypass, owns bool
		err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_collection_routing),(SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user),(SELECT pg_get_userbyid(relowner)=current_user FROM pg_class WHERE oid='workflow_collection_routing'::regclass)`).Scan(&count, &bypass, &owns)
		tx.Tx.Rollback(f.ctx)
		if err != nil || count != 0 || bypass || owns {
			t.Fatal("routing RLS requires a non-owner runtime role without bypass", count, bypass, owns, err)
		}
	}
	originals := map[string][]byte{}
	rows, err := f.admin.Query(f.ctx, `SELECT event_id::text,payload FROM events WHERE resource_id=$1 AND kind IN ('WorkflowCollectionRoutingChanged','WorkflowCommandCompleted')`, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var payload []byte
		if err = rows.Scan(&id, &payload); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		originals[id] = append([]byte(nil), payload...)
	}
	rows.Close()
	if rows.Err() != nil || len(originals) != 4 {
		t.Fatal("missing original routing journal records", len(originals), rows.Err())
	}
	private, err := f.s.CollectionRoutingStatus(f.ctx, f.scope, a.JobID, a.ID)
	if err != nil || !bytes.Contains(private.Definition, []byte(captured.Inputs[0].ID)) {
		t.Fatal("owner lost original plan bindings", err)
	}
	events, err := f.s.Custody.DB.Events(f.ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := f.s.Custody.DB.SnapshotEvents(f.ctx, peer, 1000, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, surface := range [][]store.Event{events, snapshot.Events} {
		seen := 0
		for _, event := range surface {
			original, ok := originals[event.ID]
			if !ok {
				continue
			}
			seen++
			var envelope struct {
				Redacted bool   `json:"redacted"`
				Hash     string `json:"source_payload_sha256"`
			}
			if json.Unmarshal(event.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(original) || bytes.Contains(event.Payload, []byte(captured.Inputs[0].ID)) || bytes.Contains(event.Payload, []byte(a.JobID)) {
				t.Fatal("routing bindings or receipts escaped their exact journal digest")
			}
		}
		if seen != len(originals) {
			t.Fatal("feed or audit lost routing journal identities", seen)
		}
	}
}

func TestCapturedRoutingGoBrowserDefinitionsKeepExactIndependentPostgresWireOrder(t *testing.T) {
	f := setup(t)
	data, err := os.ReadFile("../../web/tests/fixtures/collection-routing.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]capturedRoutingBrowserFixture
	if json.Unmarshal(data, &fixtures) != nil || len(fixtures) != 2 {
		t.Fatal("captured routing fixture")
	}
	definitions := []CollectionRoutingDefinition{}
	for _, fixture := range fixtures {
		definitions = append(definitions, fixture.Preview.Definition)
	}
	large := fixtures["local"].Preview.Definition
	large.Inputs = nil
	for i := 0; i < 64; i++ {
		large.Inputs = append(large.Inputs, CollectionRoutingBinding{InputID: fmt.Sprintf("00000000-0000-0000-0000-%012d", 100+i), FileID: fmt.Sprintf("00000000-0000-0000-0000-%012d", 200+i), PlanHash: strings.Repeat("e", 64)})
	}
	definitions = append(definitions, large)
	for _, definition := range definitions {
		raw, hash, err := digest(definition)
		if err != nil {
			t.Fatal(err)
		}
		var wire, actualHash string
		if err = f.admin.QueryRow(f.ctx, `SELECT freightctl_collection_routing_wire($1::jsonb),encode(sha256(convert_to(freightctl_collection_routing_wire($1::jsonb),'UTF8')),'hex')`, raw).Scan(&wire, &actualHash); err != nil || !bytes.Equal(raw, []byte(wire)) || hash != actualHash {
			t.Fatal("PostgreSQL changed typed Go wire order or approval fingerprint", err)
		}
	}
}

func TestCapturedRoutingWithdrawalWorksAfterOriginalOrTargetApprovalRevocation(t *testing.T) {
	for _, original := range []bool{true, false} {
		t.Run(fmt.Sprintf("original=%t", original), func(t *testing.T) {
			f, captured, x, old := capturedRoutingAuthorizationFixture(t)
			a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "proposal-before-revocation")
			ref := x.Workflow
			if original {
				ref = old
			}
			if _, err := f.s.Decide(f.ctx, f.scope, ref.ID, ref.Version, "revoke-routing-workflow", "revoke", Decision{Hash: ref.Hash, Revision: 2}); err != nil {
				t.Fatal(err)
			}
			_, err := f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, "cannot-approve-revoked", "approve", Decision{Hash: a.Hash, Revision: a.Revision})
			expected := store.ErrState
			if original {
				expected = store.ErrCollection
			}
			if !errors.Is(err, expected) {
				t.Fatal("revoked capture or target approval was repaired implicitly", err)
			}
			tx, err := f.s.collectionBegin(f.ctx, f.scope, "workflow_approve", "workflow_execute", "read", "write", "list")
			if err != nil {
				t.Fatal(err)
			}
			r, err := tx.CollectionRouting(f.ctx, a.JobID, a.ID, true)
			if err != nil {
				tx.Tx.Rollback(f.ctx)
				t.Fatal(err)
			}
			r.State, r.Revision, r.ApprovalAuthority = "approved", 2, tx.AuthorityRevision
			err = tx.SaveCollectionRouting(f.ctx, r, 1)
			tx.Tx.Rollback(f.ctx)
			collectionSQLRefusal(t, err)
			a = decideRoutingAuthorization(t, f, a, "withdraw", "withdraw-revoked-proposal")
			if a.State != "withdrawn" {
				t.Fatal("revoked source stranded a nonexecuting proposal")
			}
		})
	}
}

func TestCapturedRoutingOriginalReceiptsSurviveStateChangesAndStalePriorDecisionCannotApprove(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	p, err := f.s.PreviewCollectionRouting(f.ctx, f.scope, captured.Job.ID, x)
	if err != nil {
		t.Fatal(err)
	}
	proposal := CollectionRoutingProposal{Selection: x, Hash: p.Hash}
	first, err := f.s.ProposeCollectionRouting(f.ctx, f.scope, captured.Job.ID, "recover-proposal", proposal)
	if err != nil {
		t.Fatal(err)
	}
	var a CollectionRoutingAction
	if json.Unmarshal(first.Resource, &a) != nil {
		t.Fatal("original proposal receipt")
	}
	decision := Decision{Hash: a.Hash, Revision: a.Revision}
	approved, err := f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, "recover-approval", "approve", decision)
	if err != nil || json.Unmarshal(approved.Resource, &a) != nil {
		t.Fatal("original approval receipt", err)
	}
	b := proposeRoutingAuthorization(t, f, a.JobID, x, "proposal-on-current-parent")
	a = decideRoutingAuthorization(t, f, a, "revoke", "intervening-revocation")
	before := routingPreviewCounts(t, f)
	for _, action := range []string{"proposal", "approval"} {
		var replayed *Result
		var original *Result
		if action == "proposal" {
			replayed, err = f.s.ProposeCollectionRouting(f.ctx, f.scope, a.JobID, "recover-proposal", proposal)
			original = first
		} else {
			replayed, err = f.s.DecideCollectionRouting(f.ctx, f.scope, a.JobID, a.ID, "recover-approval", "approve", decision)
			original = approved
		}
		if err != nil || !replayed.Replayed || !bytes.Equal(replayed.Resource, original.Resource) {
			t.Fatal("state change replaced an original-key receipt", action, err)
		}
	}
	if after := routingPreviewCounts(t, f); after != before {
		t.Fatal("receipt recovery created a new routing effect")
	}
	if _, err = f.s.DecideCollectionRouting(f.ctx, f.scope, b.JobID, b.ID, "stale-prior-cannot-approve", "approve", Decision{Hash: b.Hash, Revision: b.Revision}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("intervening revocation did not invalidate the proposal's prior decision", err)
	}
	actual, err := f.s.CollectionRoutingStatus(f.ctx, f.scope, a.JobID, a.ID)
	if err != nil || actual.State != "revoked" || actual.Revision != a.Revision {
		t.Fatal("receipt replay restored revoked execution authority", err)
	}
	b = decideRoutingAuthorization(t, f, b, "withdraw", "withdraw-stale-proposal")
	if b.State != "withdrawn" {
		t.Fatal("cannot retire stale nonexecuting review")
	}
	view, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
	if err != nil || !reflect.DeepEqual(view.Job, captured.Job) {
		t.Fatal("routing control changed original capture", err)
	}
}
