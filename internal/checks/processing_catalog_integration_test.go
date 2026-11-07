//go:build integration

package checks

import (
	"encoding/json"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingCatalogActualActorIsolationLatestRevisionAndWithdrawnApproval(t *testing.T) {
	x := independentProcessingFixture(t)
	page, err := x.workflows.ProcessingWorkflows(x.f.ctx, x.worker, "", 1)
	if err != nil || len(page.Workflows) != 1 || page.Workflows[0].ID != x.cfg.ID || page.Workflows[0].State != "draft" || page.Workflows[0].ApprovalCurrent || !page.Workflows[0].OutputPolicyCurrent {
		t.Fatal("draft catalog facts", err)
	}
	own, err := x.workflows.ProcessingWorkflows(x.f.ctx, x.reviewer, "", 25)
	if err != nil || len(own.Workflows) != 0 {
		t.Fatal("review grant listed another actor's workflows", err)
	}
	approveIndependentProcessing(t, x)
	page, err = x.workflows.ProcessingWorkflows(x.f.ctx, x.worker, "", 1)
	if err != nil || len(page.Workflows) != 1 || !page.Workflows[0].ApprovalCurrent {
		t.Fatal("current independent approval missing", err)
	}
	if _, err = x.workflows.DecideProcessingReview(x.f.ctx, x.reviewer, x.review.ID, "catalog-withdraw-review", "withdraw", workflow.Decision{Hash: x.review.Hash, Revision: x.review.Revision}); err != nil {
		t.Fatal(err)
	}
	page, err = x.workflows.ProcessingWorkflows(x.f.ctx, x.worker, "", 1)
	if err != nil || page.Workflows[0].ApprovalCurrent || page.Workflows[0].State != "approved" {
		t.Fatal("catalog confused historical approval with live review", err)
	}
	cfg, err := x.workflows.Configuration(x.f.ctx, x.worker, x.cfg.ID, x.cfg.Version)
	if err != nil {
		t.Fatal(err)
	}
	var definition workflow.Definition
	if workflow.Decode(cfg.Definition, &definition) != nil {
		t.Fatal("task")
	}
	definition.Name = "A newer unapproved task revision"
	drafted, err := x.workflows.Draft(x.f.ctx, x.worker, "catalog-newer-draft", workflow.DraftRequest{ID: cfg.ID, ExpectedVersion: cfg.Version, Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var newer store.Configuration
	if json.Unmarshal(drafted.Resource, &newer) != nil {
		t.Fatal("newer draft")
	}
	page, err = x.workflows.ProcessingWorkflows(x.f.ctx, x.worker, "", 1)
	if err != nil || len(page.Workflows) != 1 || page.Workflows[0].Version != 2 || page.Workflows[0].Hash != newer.Hash || page.Workflows[0].State != "draft" {
		t.Fatal("catalog presented an older approved version as latest", err)
	}
	for i := 0; i < 2; i++ {
		definition.Name += " next"
		if _, err = x.workflows.Draft(x.f.ctx, x.worker, "catalog-another-"+string(rune('a'+i)), workflow.DraftRequest{Definition: definition}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	after := ""
	for i := 0; i < 4; i++ {
		p, err := x.workflows.ProcessingWorkflows(x.f.ctx, x.worker, after, 1)
		if err != nil || len(p.Workflows) != 1 || seen[p.Workflows[0].ID] {
			t.Fatal("catalog pagination duplicated,skipped or disclosed a family", err)
		}
		seen[p.Workflows[0].ID] = true
		if p.Next == "" {
			break
		}
		if p.Next != p.Workflows[0].ID {
			t.Fatal("cursor does not name the last authorized family")
		}
		after = p.Next
	}
	if len(seen) != 3 {
		t.Fatal("catalog did not page all three owned families")
	}
	// A family whose newest version uses another workflow profile must not
	// reappear as an older processing task in this profile-specific catalog.
	rootDraft, err := x.workflows.Draft(x.f.ctx, x.f.scope, "catalog-root-processing", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var root store.Configuration
	if json.Unmarshal(rootDraft.Resource, &root) != nil {
		t.Fatal("root task")
	}
	legacy := workflow.Definition{Schema: 1, Name: "A different legacy profile", Steps: []workflow.Step{{ID: "deliver", Kind: "sftp.deliver", Connection: workflow.Reference{ID: x.f.connection.ID, Version: x.f.connection.Version, Hash: x.f.connection.Hash}, Filename: "output.csv"}}}
	if _, err = x.workflows.Draft(x.f.ctx, x.f.scope, "catalog-root-legacy", workflow.DraftRequest{ID: root.ID, ExpectedVersion: root.Version, Definition: legacy}); err != nil {
		t.Fatal(err)
	}
	rootPage, err := x.workflows.ProcessingWorkflows(x.f.ctx, x.f.scope, "", 25)
	if err != nil || len(rootPage.Workflows) != 0 {
		t.Fatal("catalog revived an old processing profile", err)
	}
}
