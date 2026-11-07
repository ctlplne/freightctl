//go:build integration

package checks

import (
	"errors"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProducerProcessingContractsActualSelectionIsReadOnlyAndKeepsIngress(t *testing.T) {
	f, s, _, output, source := producerProjectionFixture(t)
	before, err := s.Policy(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	var eventsBefore, eventsAfter int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	}
	ordinary, err := s.DescribeProcessing(f.ctx, f.scope, source.ID)
	if err != nil || ordinary.Profile != "record-processing-contracts-v1" || ordinary.OutputBinding != nil || ordinary.OutputPolicy.Reference.ID != before.ID {
		t.Fatal("default metadata selection changed", err)
	}
	ref := store.OnboardingReference{ID: output.ID, Version: output.Version, Hash: output.Hash}
	selected, err := s.DescribeProcessingOutput(f.ctx, f.scope, source.ID, ref)
	if err != nil || selected.Profile != "record-processing-contracts-v2" || selected.OutputBinding == nil || selected.OutputPolicy.Reference != ref || selected.OutputPolicy.State != "output_active" || selected.Source.ID != source.ID {
		t.Fatal("explicit output selection lost exact source/producer/contract", err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&eventsAfter); err != nil || eventsAfter != eventsBefore {
		t.Fatal("metadata selection created an event or effect", err)
	}
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Other producer metadata caller", Root: "/", Permissions: []string{"read", "write", "check_run", "workflow_manage", "workflow_execute"}}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, f.scope, "contracts-other-producer", account); err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	if _, err = s.DescribeProcessingOutput(f.ctx, other, source.ID, ref); !errors.Is(err, store.ErrRevision) {
		t.Fatal("another producer borrowed contract metadata", err)
	}
	if _, err = s.RevokeOutputPolicy(f.ctx, f.scope, output.ID, output.Version, "contracts-revoke-output", PolicyDecision{Hash: output.Hash, Version: output.Version, Revision: output.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DescribeProcessingOutput(f.ctx, f.scope, source.ID, ref); !errors.Is(err, store.ErrRevision) {
		t.Fatal("revoked output contract remained selectable", err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.ID != before.ID || current.Hash != before.Hash || current.Version != before.Version || current.State != "active" {
		t.Fatal("metadata selection replaced default ingress", err)
	}
}
