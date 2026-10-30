//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func exchangeReviewFixture(t *testing.T) (*fixture, OnboardingExchangeRequest) {
	t.Helper()
	f := setup(t)
	_, probeRequest := probePlan(t, f)
	probe := startProbe(t, f, "review-probe", probeRequest)
	workflow := f.approved(t, f.definition())
	started, err := f.s.Run(f.ctx, f.scope, "review-run", RunRequest{Workflow: Reference{ID: workflow.ID, Version: workflow.Version, Hash: workflow.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(started.Resource, &run) != nil {
		t.Fatal("run result")
	}
	return f, OnboardingExchangeRequest{Plan: probeRequest.Plan, RequirementID: probeRequest.RequirementID, ProbeID: probe.ID, RunID: run.ID, StepID: "first", ExpectedAuthority: 1}
}

func TestOnboardingExchangeReviewReadsOnlyExactScopedStoredEvidence(t *testing.T) {
	f, r := exchangeReviewFixture(t)
	var before, after int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	first, err := f.s.ReviewOnboardingExchange(f.ctx, f.scope, r)
	if err != nil || first.Ready || first.ProductionActive || first.ExternalContact || first.Reason != "probe_not_succeeded" || first.Snapshot.ObservedReceipt != "none" || first.BusinessAcceptance != "unknown" {
		t.Fatal(first, err)
	}
	second, err := f.s.ReviewOnboardingExchange(f.ctx, f.scope, r)
	if err != nil || first.Hash != second.Hash || first.Snapshot.Delivery != second.Snapshot.Delivery {
		t.Fatal("read-only repeated snapshot changed", first, second, err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil || before != after {
		t.Fatal("review changed domain state", before, after, err)
	}
	for _, field := range []string{"plan", "requirement", "authority", "probe", "run", "step"} {
		changed := r
		want := store.ErrRevision
		switch field {
		case "plan":
			changed.Plan.Version++
		case "requirement":
			changed.RequirementID = secure.NewID()
		case "authority":
			changed.ExpectedAuthority++
		case "probe":
			changed.ProbeID = secure.NewID()
			want = store.ErrNotFound
		case "run":
			changed.RunID = secure.NewID()
			want = store.ErrNotFound
		case "step":
			changed.StepID = "different"
		}
		if _, err = f.s.ReviewOnboardingExchange(f.ctx, f.scope, changed); !errors.Is(err, want) {
			t.Fatal(field, err)
		}
	}
	if _, err = f.s.RevokeConnection(f.ctx, f.scope, f.connection.ID, f.connection.Version, "review-revoke", Decision{Hash: f.connection.Hash, Revision: f.connection.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.ReviewOnboardingExchange(f.ctx, f.scope, r); !errors.Is(err, store.ErrRevision) {
		t.Fatal("revoked connection qualified current review", err)
	}
}

func TestOnboardingExchangeReviewCannotReadAnotherActorsProbeOrRun(t *testing.T) {
	f, r := exchangeReviewFixture(t)
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
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	if _, err = f.s.ReviewOnboardingExchange(f.ctx, other, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("cross-actor evidence disclosed", err)
	}
}
