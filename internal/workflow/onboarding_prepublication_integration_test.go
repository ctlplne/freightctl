//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func prepublicationSelection(t *testing.T, r OnboardingHandoffSelection) OnboardingHandoffSelection {
	t.Helper()
	data, _ := json.Marshal(r)
	var value map[string]any
	_ = json.Unmarshal(data, &value)
	value["profile"] = "prepublication-production-handoff-v1"
	data, _ = json.Marshal(value)
	if err := Decode(data, &r); err != nil {
		t.Fatal("explicit pre-publication review profile unavailable", err)
	}
	return r
}

func TestOnboardingPrepublicationHandoffRejectsPublicationAndLiveLease(t *testing.T) {
	for _, state := range []string{"staging", "publishing"} {
		t.Run(state, func(t *testing.T) {
			f, original, selection := prepublicationFixture(t, state)
			selection = prepublicationSelection(t, selection)
			if _, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
				t.Fatal("live/publication source admitted", err)
			}
			if state == "publishing" {
				view, err := f.s.Status(f.ctx, f.scope, original.Run.ID)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
				if err != nil {
					t.Fatal(err)
				}
				d, err := tx.Delivery(f.ctx, view.Steps[0].DeliveryID, true)
				if err != nil {
					t.Fatal(err)
				}
				previous := d.Revision
				d.Revision++
				d.State = "ambiguous"
				d.LeaseOwner = ""
				d.LeaseUntil = nil
				if err = tx.SaveDelivery(f.ctx, d, previous); err != nil {
					t.Fatal(err)
				}
				if err = tx.Tx.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
					t.Fatal("ambiguous source admitted", err)
				}
			}
		})
	}
}

func TestOnboardingPrepublicationHandoffWaitsForOriginalLeaseAndFencesWorker(t *testing.T) {
	f, original, selection := prepublicationFixture(t, "staging")
	selection = prepublicationSelection(t, selection)
	if _, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
		t.Fatal("live lease admitted", err)
	}
	view, err := f.s.Status(f.ctx, f.scope, original.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var expired bool
	deadline := time.Now().Add(35 * time.Second)
	for !expired {
		if err = f.admin.QueryRow(f.ctx, `SELECT lease_until<=clock_timestamp() FROM delivery_intents WHERE delivery_id=$1`, view.Steps[0].DeliveryID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if !expired {
			if time.Now().After(deadline) {
				t.Fatal("original 30-second lease did not expire")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	_, h, _ := proposeHandoff(t, f, selection, "expired-stage-handoff")
	h, _ = decideHandoff(t, f, h, "approve", "expired-stage-approve")
	h, _ = decideHandoff(t, f, h, "execute", "expired-stage-execute")
	old, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
	if err != nil || old.Status.Run.State != "cancelled" || old.Status.Steps[0].Attempts != 1 || h.NewRunID == "" {
		t.Fatal("expired stage lost", old, err)
	}
	worker := &delivery.Service{Custody: f.s.Custody}
	if _, _, err = worker.Claim(f.ctx, f.scope, view.Steps[0].DeliveryID, secure.NewID()); err == nil {
		t.Fatal("late original worker claimed cancelled stage")
	}
}

func TestOnboardingPrepublicationHandoffRejectsIncompleteOrExtraJournal(t *testing.T) {
	for _, mode := range []string{"orphan-publication", "missing-field", "duplicate-revision", "over-budget"} {
		t.Run(mode, func(t *testing.T) {
			f, _, selection := prepublicationFixture(t, "retry")
			selection = prepublicationSelection(t, selection)
			_, h, _ := proposeHandoff(t, f, selection, "journal-reviewed")
			h, _ = decideHandoff(t, f, h, "approve", "journal-approved")
			tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			p, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection)
			if err != nil {
				t.Fatal(err)
			}
			id := p.Definition.Source.Delivery.ID
			payload := map[string]any{"revision": p.Definition.Source.Delivery.Revision + 1, "state": "publishing"}
			count := 1
			if mode == "duplicate-revision" {
				payload["revision"] = p.Definition.Source.Delivery.Revision
				payload["state"] = "retry"
			}
			if mode == "missing-field" {
				delete(payload, "state")
			}
			if mode == "over-budget" {
				count = 257
			}
			for i := 0; i < count; i++ {
				if _, err = tx.Append(f.ctx, "DeliveryTransitioned", id, payload); err != nil {
					t.Fatal(err)
				}
			}
			if err = tx.Tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
				t.Fatal("incomplete/extra journal admitted", mode, err)
			}
			if _, err = f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "journal-execute", Decision{Hash: h.Hash, Revision: h.Revision}); !errors.Is(err, store.ErrState) {
				t.Fatal("changed journal executed", mode, err)
			}
		})
	}
}

func prepublicationFixture(t *testing.T, state string) (*fixture, OnboardingProductionResult, OnboardingHandoffSelection) {
	t.Helper()
	f, release, prior, _ := handoffFixture(t)
	_, run, _ := productionIntent(t, f, release, prior.Dispatch.Definition.RequirementID, f.file.ID, "prepublication-source")
	view, err := f.s.Status(f.ctx, f.scope, run.Run.ID)
	if err != nil {
		t.Fatal(err)
	}
	worker := &delivery.Service{Custody: f.s.Custody}
	d, _, err := worker.Claim(f.ctx, f.scope, view.Steps[0].DeliveryID, secure.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if state != "staging" {
		tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		previous := d.Revision
		d.Revision++
		d.State = state
		if state == "retry" || state == "blocked" {
			d.LeaseOwner = ""
			d.LeaseUntil = nil
		}
		d.Observation = json.RawMessage(`{"code":"fixture_prepublication_boundary"}`)
		if err = tx.SaveDelivery(f.ctx, d, previous); err != nil {
			t.Fatal(err)
		}
		if err = tx.Tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
	}
	release = decideRelease(t, f, release, "suspend")
	release = decideRelease(t, f, release, "activate")
	return f, run, OnboardingHandoffSelection{SourceRunID: run.Run.ID, SourceHash: run.Dispatch.Hash, Target: store.OnboardingActivationReference{ID: release.ID, Revision: release.Revision, Hash: release.Hash}, FileID: f.file.ID}
}

func TestOnboardingPrepublicationHandoffPreservesAttemptAndOriginalReceipt(t *testing.T) {
	for _, state := range []string{"retry", "blocked"} {
		t.Run(state, func(t *testing.T) {
			f, original, selection := prepublicationFixture(t, state)
			if _, err := f.s.PreviewOnboardingHandoff(f.ctx, f.scope, selection); !errors.Is(err, store.ErrState) {
				t.Fatal("untouched profile admitted recorded attempt", err)
			}
			selection = prepublicationSelection(t, selection)
			_, h, _ := proposeHandoff(t, f, selection, "prepublication-review")
			h, _ = decideHandoff(t, f, h, "approve", "prepublication-approve")
			h, _ = decideHandoff(t, f, h, "execute", "prepublication-execute")
			old, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
			if err != nil || old.Status.Run.State != "cancelled" || old.Status.Steps[0].Attempts != 1 || old.Dispatch.Hash != original.Dispatch.Hash {
				t.Fatal("original attempt/meaning lost", old, err)
			}
			next, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, h.NewRunID)
			if err != nil || next.Status.Run.State != "queued" || next.Status.Steps[0].Attempts != 0 || next.Status.Run.Source != *f.file {
				t.Fatal("replacement", next, err)
			}
			replayed, err := f.s.StartOnboardingProduction(f.ctx, f.scope, "prepublication-source", OnboardingProductionStart{Definition: original.Dispatch.Definition})
			if err != nil || !replayed.Replayed {
				t.Fatal("original queue receipt lost", err)
			}
			var receipt OnboardingProductionResult
			if json.Unmarshal(replayed.Resource, &receipt) != nil || receipt.Run.ID != original.Run.ID || receipt.Dispatch.Hash != original.Dispatch.Hash || receipt.Run.State != "queued" {
				t.Fatal("historical receipt rewritten", receipt)
			}
		})
	}
}

func TestOnboardingPrepublicationHandoffRollbackAndForgedCancellation(t *testing.T) {
	f, original, selection := prepublicationFixture(t, "blocked")
	selection = prepublicationSelection(t, selection)
	preview, h, _ := proposeHandoff(t, f, selection, "atomic-prepublication")
	fake := preview.Definition
	proof := *fake.Prepublication
	proof.HistoryHash = strings.Repeat("f", 64)
	fake.Prepublication = &proof
	if _, err := f.s.ProposeOnboardingHandoff(f.ctx, f.scope, "forged-history", OnboardingHandoffProposal{Definition: fake}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("invented history accepted", err)
	}
	h, _ = decideHandoff(t, f, h, "approve", "atomic-prepublication-approve")
	var before int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_dispatches`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_prepublication_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture receipt unavailable';END $$;CREATE TRIGGER freightctl_prepublication_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_prepublication_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DecideOnboardingHandoff(f.ctx, f.scope, h.ID, "execute", "atomic-prepublication-execute", Decision{Hash: h.Hash, Revision: h.Revision}); err == nil {
		t.Fatal("receipt failure acknowledged")
	}
	old, err := f.s.OnboardingProductionStatus(f.ctx, f.scope, original.Run.ID)
	if err != nil || old.Status.Steps[0].State != "blocked" || old.Status.Steps[0].Attempts != 1 {
		t.Fatal("rollback lost original", old, err)
	}
	var after int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_dispatches`).Scan(&after); err != nil || before != after {
		t.Fatal("orphan successor", before, after, err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	d, err := tx.Delivery(f.ctx, preview.Definition.Source.Delivery.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	prior := d.Revision
	d.Revision++
	d.State = "cancelled"
	d.Observation = json.RawMessage(`{"code":"onboarding_handoff","handoff_id":"` + h.ID + `"}`)
	if err = tx.SaveDelivery(f.ctx, d, prior); err != nil {
		t.Fatal(err)
	}
	var pgerr *pgconn.PgError
	if err = tx.Tx.Commit(f.ctx); !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatal("forged blocked cancellation committed", err)
	}
}
