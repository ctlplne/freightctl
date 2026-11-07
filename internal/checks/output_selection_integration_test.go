//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingOutputSelectionActualTypedTaskPinsProducerContractWithoutChangingIngress(t *testing.T) {
	f, s, other, _, input := outputProducerFixture(t)
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Output contract task owner", Root: "/processor", Permissions: []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"}}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "selection-task-owner", account); err != nil {
		t.Fatal(err)
	}
	actor := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	_, output := registerOutputFixture(t, f, s, account, input)
	ref := store.OnboardingReference{ID: output.Policy.ID, Version: output.Policy.Version, Hash: output.Policy.Hash}
	for _, candidate := range []store.Scope{other, f.scope} {
		tx, err := s.Custody.DB.Begin(f.ctx, candidate)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.ProcessingPolicy(f.ctx, ref)
		tx.Tx.Rollback(f.ctx)
		if !errors.Is(err, store.ErrRevision) {
			t.Fatal("other actor or root administrator selected another producer's contract", err)
		}
	}
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "total"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Producer contract task metadata", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", OutputPolicy: workflow.Reference{ID: ref.ID, Version: ref.Version, Hash: ref.Hash}, Definition: rules, Reason: "Keep incoming CSV policy while selecting exact JSON output contract"}}
	wf := &workflow.Service{Custody: s.Custody, Processor: s}
	draft, err := wf.Draft(f.ctx, actor, "selected-output-task-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("task draft")
	}
	if _, err = wf.Decide(f.ctx, actor, cfg.ID, cfg.Version, "selected-output-task-approve", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	page, err := wf.ProcessingWorkflows(f.ctx, actor, "", 25)
	if err != nil || len(page.Workflows) != 1 || !page.Workflows[0].ApprovalCurrent || !page.Workflows[0].OutputPolicyCurrent {
		t.Fatal("catalog did not observe exact producer contract separately from approval", err)
	}
	if _, err = s.RevokeOutputPolicy(f.ctx, f.scope, ref.ID, ref.Version, "selection-output-revoke", PolicyDecision{Hash: ref.Hash, Version: ref.Version, Revision: output.Policy.Revision}); err != nil {
		t.Fatal(err)
	}
	page, err = wf.ProcessingWorkflows(f.ctx, actor, "", 25)
	if err != nil || len(page.Workflows) != 1 || page.Workflows[0].OutputPolicyCurrent || !page.Workflows[0].ApprovalCurrent {
		t.Fatal("revocation changed historical task approval or retained current policy", err)
	}
	if _, err = wf.Draft(f.ctx, actor, "stale-selected-output-task", workflow.DraftRequest{Definition: definition}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("revoked producer policy selected for a new task", err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.ID != input.ID || current.Hash != input.Hash || current.Version != input.Version || current.State != "active" {
		t.Fatal("task metadata changed default ingress", err)
	}
}
