//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

func capturedRoutingIndependentSourceFixture(t *testing.T) (*fixture, *CollectionView, CollectionRoutingSelection, ConnectionView) {
	t.Helper()
	f := setup(t)
	request := f.request
	request.Directory = "/source"
	r, err := f.s.RegisterConnection(f.ctx, f.scope, "independent-routing-source", request)
	if err != nil {
		t.Fatal(err)
	}
	var connection ConnectionView
	if json.Unmarshal(r.Resource, &connection) != nil || connection.ID == f.connection.ID {
		t.Fatal("source must have an independent connection family")
	}
	d := f.definition()
	source := collectionTestSource()
	source.Directory = "/"
	source.Connection = Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}
	d.Schema, d.Source = 2, &source
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[0].ID}}}
	original := f.approved(t, d)
	job, owner, inputs := sealedCollectionFixture(t, f, CollectionSelection{Workflow: Reference{ID: original.ID, Version: original.Version, Hash: original.Hash}, Timeout: 120, Authority: 1}, "independent-source-capture", "abc", "def")
	captured := finishSealedCollection(t, f, job, owner, inputs)
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: d.Steps[1].ID}}}
	target := revisedCollectionRoutingWorkflow(t, f, original, d)
	return f, captured, CollectionRoutingSelection{Collection: Decision{Hash: job.Hash, Revision: captured.Job.Revision}, Workflow: Reference{ID: target.ID, Version: target.Version, Hash: target.Hash}, Authority: 1}, connection
}

func TestCapturedRoutingSourceRevocationBlocksNewAdmissionAndAlreadyQueuedEffects(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(fmt.Sprintf("already_queued=%t", queued), func(t *testing.T) {
			f, captured, x, source := capturedRoutingIndependentSourceFixture(t)
			a := proposeRoutingAuthorization(t, f, captured.Job.ID, x, "source-revocation-propose")
			a = decideRoutingAuthorization(t, f, a, "approve", "source-revocation-approve")
			if queued {
				if _, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "source-revocation-admit", x.Collection); err != nil {
					t.Fatal(err)
				}
			}
			assigned := 0
			if queued {
				assigned = 2
			}
			view := assertCapturedRoutingRuns(t, f, captured, x, a.ID, assigned)
			if _, err := f.s.RevokeConnection(f.ctx, f.scope, source.ID, source.Version, "revoke-independent-routing-source", Decision{Hash: source.Hash, Revision: source.Revision}); err != nil {
				t.Fatal(err)
			}
			// Keep the receiver active so this failure proves the original source
			// binding still matters after its bytes have been captured locally.
			var receiverState string
			if err := f.admin.QueryRow(f.ctx, `SELECT state FROM connection_revisions WHERE connection_id=$1 AND version=$2`, f.connection.ID, f.connection.Version).Scan(&receiverState); err != nil || receiverState != "active" {
				t.Fatal("source revocation also changed the receiver", receiverState, err)
			}
			before := routingPreviewCounts(t, f)
			if _, err := f.s.RefreshCollection(f.ctx, f.scope, captured.Job.ID, "revoked-source-cannot-admit", x.Collection); !errors.Is(err, store.ErrCollection) {
				t.Fatal("approved corrected rules bypassed revoked source authority", err)
			}
			for _, input := range view.Inputs {
				if input.RunID == nil {
					continue
				}
				status, err := f.s.Status(f.ctx, f.scope, *input.RunID)
				if err != nil {
					t.Fatal(err)
				}
				id := status.Steps[0].DeliveryID
				if _, _, err = (&delivery.Service{Custody: f.s.Custody}).Claim(f.ctx, f.scope, id, secure.NewID()); !errors.Is(err, store.ErrCollection) {
					t.Fatal("source revocation left a queued effect runnable", err)
				}
				var attempts int
				if err = f.admin.QueryRow(f.ctx, `SELECT attempts FROM delivery_intents WHERE delivery_id=$1`, id).Scan(&attempts); err != nil || attempts != 0 {
					t.Fatal("revoked source consumed a transfer attempt", attempts, err)
				}
			}
			if routingPreviewCounts(t, f) != before {
				t.Fatal("revoked source left partial admission or effect records")
			}
			after, err := f.s.CollectionStatus(f.ctx, f.scope, captured.Job.ID)
			if err != nil || !reflect.DeepEqual(after.Job, captured.Job) || !reflect.DeepEqual(after.Inputs, view.Inputs) {
				t.Fatal("source revocation rewrote original captured bytes or assignments", err)
			}
			for _, input := range after.Inputs {
				file, body, err := f.s.Custody.DownloadPath(f.ctx, f.scope, input.Target)
				if err != nil {
					t.Fatal("source revocation removed access to already accepted local bytes", err)
				}
				body.Close()
				if file.ID != *input.FileID || file.SHA256 != input.SHA256 {
					t.Fatal("local custody no longer identifies the accepted revision")
				}
			}
		})
	}
}
