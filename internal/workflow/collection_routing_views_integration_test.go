//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestCapturedRoutingCurrentMetadataKeepsRevokedHistoryWithoutExecutionAuthority(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	before := routingPreviewCounts(t, f)
	v, err := f.s.CurrentCollectionRouting(f.ctx, f.scope, captured.Job.ID)
	if err != nil || v.Authorization != nil || v.Workflow != nil || v.Current || len(v.Effects) != 0 {
		t.Fatal("absent routing decision invented authority or a target", v, err)
	}
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "metadata-proposal")
	v, err = f.s.CurrentCollectionRouting(f.ctx, f.scope, captured.Job.ID)
	if err != nil || v.Authorization != nil || v.Current || v.Proposal == nil || v.Proposal.ID != a.ID {
		t.Fatal("pending proposal became effective", v, err)
	}
	detail, err := f.s.CollectionRoutingDetails(f.ctx, f.scope, a.JobID, a.ID)
	if err != nil || detail.Authorization.State != "proposed" || detail.Current || detail.Workflow.Hash != x.Workflow.Hash || len(detail.Effects) != 2 {
		t.Fatal("cannot inspect exact pending target", detail, err)
	}
	a = decideRoutingAuthorization(t, f, a, "approve", "metadata-approval")
	v, err = f.s.CurrentCollectionRouting(f.ctx, f.scope, a.JobID)
	if err != nil || v.Authorization.ID != a.ID || !v.Current || v.Workflow.Hash != x.Workflow.Hash || !reflect.DeepEqual(v.Effects, detail.Effects) {
		t.Fatal("effective approval metadata is not exact", v, err)
	}
	counts := routingPreviewCounts(t, f)
	if counts[0] != before[0] || counts[1] != before[1] {
		t.Fatal("metadata or approval created a run")
	}
	if _, err = f.s.Decide(f.ctx, f.scope, x.Workflow.ID, x.Workflow.Version, "metadata-target-revoke", "revoke", Decision{Hash: x.Workflow.Hash, Revision: 2}); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.CurrentCollectionRouting(f.ctx, f.scope, a.JobID)
	if err != nil || v.Current || v.Workflow.State != "revoked" || !reflect.DeepEqual(v.Effects, detail.Effects) {
		t.Fatal("target revocation erased history or left authority", v, err)
	}
	if _, err = f.s.CancelCollection(f.ctx, f.scope, a.JobID, "metadata-source-stop", x.Collection); err != nil {
		t.Fatal(err)
	}
	a = decideRoutingAuthorization(t, f, a, "revoke", "metadata-routing-revoke")
	v, err = f.s.CollectionRoutingDetails(f.ctx, f.scope, a.JobID, a.ID)
	if err != nil || v.Current || v.Authorization.State != "revoked" || !reflect.DeepEqual(v.Effects, detail.Effects) || v.Authorization.Hash != a.Hash {
		t.Fatal("stopping original capture erased the reviewed history", v, err)
	}
	raw, err := json.Marshal(v)
	if err != nil || bytes.Contains(raw, []byte(f.request.KeyFile)) || bytes.Contains(raw, []byte(f.request.HostPublicFile)) || bytes.Contains(raw, []byte("public_packets")) {
		t.Fatal("metadata disclosed key contents or protected file references", err)
	}
	peer, _ := approvalPeer(t, f, "Other routing metadata reader", append([]string{}, store.DefaultPermissions...))
	if _, err = f.s.CurrentCollectionRouting(f.ctx, peer, a.JobID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("effective routing disclosed another actor's capture", err)
	}
	if _, err = f.s.CollectionRoutingDetails(f.ctx, peer, a.JobID, a.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("historical routing metadata disclosed another actor's approval", err)
	}
}

func TestCapturedRoutingReadOnlyReceiptRecoveryCannotCreateOrRestoreDecisions(t *testing.T) {
	f, captured, x, _ := capturedRoutingAuthorizationFixture(t)
	before := routingPreviewCounts(t, f)
	if _, err := f.s.CollectionRoutingReceipt(f.ctx, f.scope, captured.Job.ID, "unknown-saved-key"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown receipt did not fail closed", err)
	}
	if after := routingPreviewCounts(t, f); before != after {
		t.Fatal("unknown saved key wrote execution state")
	}
	a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "saved-key-proposal")
	a = decideRoutingAuthorization(t, f, a, "approve", "saved-key-approval")
	a = decideRoutingAuthorization(t, f, a, "revoke", "saved-key-revocation")
	before = routingPreviewCounts(t, f)
	for _, key := range []string{"saved-key-proposal", "saved-key-approval", "saved-key-revocation"} {
		r, err := f.s.CollectionRoutingReceipt(f.ctx, f.scope, a.JobID, key)
		if err != nil || !r.Replayed {
			t.Fatal("lost original receipt", err)
		}
		var action CollectionRoutingAction
		if json.Unmarshal(r.Resource, &action) != nil || action.ID != a.ID || action.Hash != a.Hash {
			t.Fatal("receipt changed the original authorization identity")
		}
	}
	if after := routingPreviewCounts(t, f); before != after {
		t.Fatal("receipt lookup wrote execution state")
	}
	current, err := f.s.CurrentCollectionRouting(f.ctx, f.scope, a.JobID)
	if err != nil || current.Current || current.Authorization.State != "revoked" {
		t.Fatal("old approval receipt restored authority", err)
	}
	peer, _ := approvalPeer(t, f, "Other receipt reader", append([]string{}, store.DefaultPermissions...))
	if _, err = f.s.CollectionRoutingReceipt(f.ctx, peer, a.JobID, "saved-key-approval"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("receipt key disclosed another actor's decision", err)
	}
}
