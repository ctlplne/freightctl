package checks

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestScopedProjectionAuthorityRequiresExplicitProcessingWithoutReleaseOrAdministration(t *testing.T) {
	tx := &store.Transaction{Root: "/payroll", Permissions: []string{"read", "write", "check_run", "workflow_manage"}}
	if err := projectionActionAuthority(tx, ScopedProjectionProfile, "workflow_manage"); err != nil {
		t.Fatal("scoped processor refused", err)
	}
	if err := projectionAuthority(tx, ProjectionReviewProfile); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("processing grant obtained legacy root administration", err)
	}
	for i := range tx.Permissions {
		copy := *tx
		copy.Permissions = append([]string{}, tx.Permissions[:i]...)
		copy.Permissions = append(copy.Permissions, tx.Permissions[i+1:]...)
		if err := projectionActionAuthority(&copy, ScopedProjectionProfile, "workflow_manage"); !errors.Is(err, store.ErrForbidden) {
			t.Fatal("missing required processing grant accepted", err)
		}
	}
	if err := projectionAuthority(tx, "invented-profile"); err == nil {
		t.Fatal("unknown authority profile accepted")
	}
	executor := *tx
	executor.Permissions = []string{"read", "write", "check_run", "workflow_execute"}
	if err := projectionActionAuthority(&executor, ScopedProjectionProfile, "workflow_execute"); err != nil {
		t.Fatal("scoped execution requires unrelated administration", err)
	}
	for _, action := range []string{"workflow_manage", "workflow_approve"} {
		if err := projectionActionAuthority(&executor, ScopedProjectionProfile, action); !errors.Is(err, store.ErrForbidden) {
			t.Fatal("execution grant became plan management/approval", err)
		}
	}
}

func TestScopedProjectionReviewPinsProfileRootAndOriginalAuthority(t *testing.T) {
	v, c, d, now := projectionReviewFixture(t)
	v.Plan.Root = "/payroll"
	v.Plan.Source.Check.Binding.Root = "/payroll"
	c.Binding, _, _ = canonical(v.Plan.Source.Check.Binding)
	got, err := projectionReviewProfile(v, c, d, now, ScopedProjectionProfile)
	if err != nil || got.Plan.Schema != 2 || got.Plan.Profile != ScopedProjectionProfile || got.Plan.Context.Root != "/payroll" {
		t.Fatal("scoped review lost its versioned root", err)
	}
	if _, err = projectionReview(v, c, d, now); err == nil {
		t.Fatal("legacy profile accepted a different root")
	}
	row, definition, _ := projectionIntentFixture(t)
	definition.Plan = got.Plan
	row.SourceID = got.Plan.Context.Source.File.ID
	row.Definition, row.Hash, _ = canonical(definition)
	if _, err = decodeProjection(row); err != nil {
		t.Fatal("durable scoped definition refused", err)
	}
	definition.Plan.Schema = 1
	row.Definition, row.Hash, _ = canonical(definition)
	if _, err = decodeProjection(row); err == nil {
		t.Fatal("scoped authority reinterpreted as legacy schema")
	}
	if projectionOptionsFor(got.Plan).Profile != ScopedProjectionProfile {
		t.Fatal("current-state revalidation dropped scoped profile")
	}
}

func TestScopedProjectionReplayCannotReinterpretChangedNamespace(t *testing.T) {
	r, d, _ := projectionIntentFixture(t)
	d.Plan.Schema = 2
	d.Plan.Profile = ScopedProjectionProfile
	d.Plan.Context.Root = "/payroll"
	r.Definition, r.Hash, _ = canonical(d)
	data, _, _ := canonical(projectionReceipt(r))
	tx := &store.Transaction{Root: "/payroll", Permissions: []string{"read", "write", "check_run", "workflow_manage"}}
	if err := projectionReplayScope(tx, data); err != nil {
		t.Fatal("original scoped receipt refused", err)
	}
	tx.Root = "/other"
	if err := projectionReplayScope(tx, data); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("root change disclosed historical private plan", err)
	}
}
