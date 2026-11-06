package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func projectionIntentFixture(t *testing.T) (*store.RecordProjection, ProjectionDefinition, time.Time) {
	t.Helper()
	v, c, p, now := projectionReviewFixture(t)
	review, err := projectionReview(v, c, p, now)
	if err != nil {
		t.Fatal(err)
	}
	d := ProjectionDefinition{Schema: 1, Plan: review.Plan, Slots: []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"}}
	wire, hash, err := canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	return &store.RecordProjection{ID: "55555555-5555-4555-8555-555555555555", SourceID: d.Plan.Context.Source.File.ID, Definition: wire, Hash: hash, State: "proposed", Revision: 1, Result: json.RawMessage(`{}`)}, d, now
}

func TestProjectionIntentDefinitionBindsAllReviewedMeaningAndOnlyOwnedSlots(t *testing.T) {
	r, d, _ := projectionIntentFixture(t)
	if _, err := decodeProjection(r); err != nil {
		t.Fatal("valid exact definition refused", err)
	}
	for _, mutate := range []func(*ProjectionDefinition){
		func(d *ProjectionDefinition) { d.Schema++ }, func(d *ProjectionDefinition) { d.Plan.Profile = "unqualified" },
		func(d *ProjectionDefinition) { d.Slots = d.Slots[:2] }, func(d *ProjectionDefinition) { d.Slots[1] = d.Slots[0] },
		func(d *ProjectionDefinition) { d.Slots[0] = d.Plan.Context.Source.File.ID }, func(d *ProjectionDefinition) { d.Slots[0] = "host/path" },
	} {
		wire, _ := json.Marshal(d)
		var changed ProjectionDefinition
		_ = json.Unmarshal(wire, &changed)
		mutate(&changed)
		r.Definition, r.Hash, _ = canonical(changed)
		if _, err := decodeProjection(r); err == nil {
			t.Fatal("invalid preapproved effects accepted")
		}
	}
	r, d, _ = projectionIntentFixture(t)
	for _, mutate := range []func(*ProjectionDefinition){
		func(d *ProjectionDefinition) { d.Plan.Context.Authority++ }, func(d *ProjectionDefinition) { d.Plan.SourcePolicy.Version++ },
		func(d *ProjectionDefinition) { d.Plan.Projection.Columns[0].Target = "redirected" }, func(d *ProjectionDefinition) { d.Plan.Context.Source.Check.ReportHash = strings.Repeat("a", 64) },
		func(d *ProjectionDefinition) { d.Plan.Context.Policy.Hash = strings.Repeat("b", 64) }, func(d *ProjectionDefinition) { d.Plan.OutputContractHash = strings.Repeat("c", 64) },
	} {
		wire, _ := json.Marshal(d)
		var changed ProjectionDefinition
		_ = json.Unmarshal(wire, &changed)
		mutate(&changed)
		r.Definition, _, _ = canonical(changed)
		if _, err := decodeProjection(r); err == nil {
			t.Fatal("review changed under its original approved hash")
		}
	}
}

func TestProjectionAttemptRequiresCurrentLeaseExactWorkerAndBoundedRetry(t *testing.T) {
	r, _, now := projectionIntentFixture(t)
	until := now.Add(time.Minute)
	r.State, r.Attempts, r.WorkerID, r.LeaseUntil = "running", 1, "66666666-6666-4666-8666-666666666666", &until
	a := ProjectionAttempt{ID: r.ID, Number: 1, WorkerID: r.WorkerID}
	if err := projectionLeaseCurrent(r, a, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*store.RecordProjection, *ProjectionAttempt){
		func(r *store.RecordProjection, a *ProjectionAttempt) { a.ID = "77777777-7777-4777-8777-777777777777" },
		func(r *store.RecordProjection, a *ProjectionAttempt) { a.Number++ }, func(r *store.RecordProjection, a *ProjectionAttempt) {
			a.WorkerID = "88888888-8888-4888-8888-888888888888"
		},
		func(r *store.RecordProjection, a *ProjectionAttempt) { r.State = "approved" }, func(r *store.RecordProjection, a *ProjectionAttempt) { r.LeaseUntil = nil },
		func(r *store.RecordProjection, a *ProjectionAttempt) { n := now; r.LeaseUntil = &n }, func(r *store.RecordProjection, a *ProjectionAttempt) { r.Attempts = 4; a.Number = 4 },
	} {
		copy, attempt := *r, a
		change(&copy, &attempt)
		if err := projectionLeaseCurrent(&copy, attempt, now); err == nil {
			t.Fatal("stale worker or exhausted attempt retained execution authority")
		}
	}
}
