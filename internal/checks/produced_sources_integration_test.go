//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func composedSourceFixture(t *testing.T) (*fixture, *Service, *store.File, store.Configuration, workflow.Definition, store.Configuration) {
	t.Helper()
	f, s, first, input, source := producerProjectionFixture(t)
	run := processingWorkflowRun(t, f, &first, source, "composition-first-run")
	work, err := f.wf.Work(f.ctx, f.scope, run.ID, "composition-first-work")
	if err != nil || work.Processing == nil {
		t.Fatal("first producer", err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	produced, err := tx.File(f.ctx, work.Processing.FileID)
	tx.Tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := decodePolicy(&input)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := NormalizeRecordProjection(policy, RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "csv", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "total", Target: "amount"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(policy, rules)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := s.RegisterOutputPolicy(f.ctx, f.scope, "composition-final-output-policy", OutputPolicyRequest{Producer: identity.Actor, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var record OutputPolicyRecord
	if json.Unmarshal(registered.Resource, &record) != nil || record.Policy == nil {
		t.Fatal("second output policy")
	}
	definition := workflow.Definition{Schema: 3, Name: "Separately approved JSON to CSV task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: record.Policy.ID, Version: record.Policy.Version, Hash: record.Policy.Hash}, Reason: "Consume the exact checked owned output under a separate approval"}}
	return f, s, produced, input, definition, *record.Policy
}

func TestComposedProducerProjectionActualFreshSourceSeparateApprovalHeldOutputAndReplay(t *testing.T) {
	f, s, produced, _, definition, output := composedSourceFixture(t)
	ref := store.OnboardingReference{ID: output.ID, Version: output.Version, Hash: output.Hash}
	if _, err := s.DescribeProcessingOutput(f.ctx, f.scope, produced.ID, ref); err == nil {
		t.Fatal("unchecked generated source described as eligible")
	}
	if _, err := s.Run(f.ctx, f.scope, produced.ID, "composition-source-fresh-check"); err != nil {
		t.Fatal(err)
	}
	metadata, err := s.DescribeProcessingOutput(f.ctx, f.scope, produced.ID, ref)
	if err != nil || metadata.Profile != "record-processing-contracts-v3" || metadata.SourceOrigin == nil || metadata.SourceOrigin.File != *produced {
		t.Fatal("source lineage metadata", err)
	}
	draft, err := f.wf.Draft(f.ctx, f.scope, "composition-second-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("second task")
	}
	request := workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: produced.ID}
	if _, err := f.wf.Run(f.ctx, f.scope, "composition-without-second-approval", request); err == nil {
		t.Fatal("first approval authorized a second task")
	}
	if _, err := f.wf.Decide(f.ctx, f.scope, cfg.ID, cfg.Version, "composition-second-approval", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	run := processingWorkflowRun(t, f, &cfg, produced, "composition-second-run")
	work, err := f.wf.Work(f.ctx, f.scope, run.ID, "composition-second-work")
	if err != nil || work.Processing == nil || work.Processing.State != "completed" || work.Processing.FileID == produced.ID || work.Status.Processing.Released {
		t.Fatal("second owned held output", err)
	}
	d, err := decodeProjection(work.Processing)
	if err != nil || d.Schema != 4 || d.Plan.Profile != ComposedProducerProjectionProfile || d.Plan.SourceOrigin == nil || *d.Plan.SourceOrigin != *metadata.SourceOrigin {
		t.Fatal("durable composed provenance", err)
	}
	for _, mutate := range []func(*store.ProducedSource){
		func(s *store.ProducedSource) { s.ProjectionHash = secure.Digest([]byte("other intent")) },
		func(s *store.ProducedSource) { s.File.EventID = secure.NewID() },
		func(s *store.ProducedSource) { s.Producer.Producer.Actor = secure.NewID() },
	} {
		changed := *d.Plan.SourceOrigin
		mutate(&changed)
		tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(changed)
		_, err = tx.Tx.Exec(f.ctx, `SELECT freightctl_produced_source_current($1,$2,$3,$4,$5::jsonb)`, f.scope.Tenant, f.scope.Partner, tx.Actor, produced.ID, raw)
		tx.Tx.Rollback(f.ctx)
		if err == nil {
			t.Fatal("SQL accepted substituted source provenance")
		}
	}
	replayed, err := f.wf.Work(f.ctx, f.scope, run.ID, "composition-second-work")
	if err != nil || !replayed.Replayed || replayed.Processing.ID != work.Processing.ID || replayed.Processing.Attempts != 1 {
		t.Fatal("composition replay duplicated the effect", err)
	}
	for _, id := range []string{produced.ID, work.Processing.FileID} {
		if _, _, err := s.Custody.Download(f.ctx, f.scope, id); !errors.Is(err, store.ErrState) {
			t.Fatal("composition released held bytes", err)
		}
	}
	id := work.Processing.FileID
	check := getCheck(t, s, f, id)
	if check.State != "held" || check.Attempts != 0 || check.PolicyID != output.ID {
		t.Fatal("second output inherited source proof")
	}
	if _, err := s.Run(f.ctx, f.scope, id, "composition-final-check"); err != nil {
		t.Fatal(err)
	}
	check = getCheck(t, s, f, id)
	if _, err := s.Release(f.ctx, f.scope, id, "composition-final-release", releaseDecision(check)); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.Download(f.ctx, f.scope, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Contains(data, []byte("account,amount,day")) || !bytes.Contains(data, []byte("0001,1.01,")) {
		t.Fatal("composed output lost exact identifier/decimal", err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current == nil {
		t.Fatal("default ingress observation", err)
	}
	var ingress Policy
	if json.Unmarshal(current.Definition, &ingress) != nil || ingress.Kind != "csv" || current.State != "active" || current.Version != 1 {
		t.Fatal("composition changed default ingress")
	}
}

func TestComposedProducerProjectionActualOtherActorAndSourceRevocationRefuseConsumption(t *testing.T) {
	f, s, produced, input, definition, output := composedSourceFixture(t)
	if _, err := s.Run(f.ctx, f.scope, produced.ID, "composition-revoke-source-check"); err != nil {
		t.Fatal(err)
	}
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Other administrator", Root: "/", Permissions: append([]string(nil), store.DefaultPermissions...)}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "composition-other-actor", account); err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	tx, err := s.Custody.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.ProducedSource(f.ctx, produced)
	tx.Tx.Rollback(f.ctx)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other administrator inherited generated source ownership", err)
	}
	draft, err := f.wf.Draft(f.ctx, f.scope, "composition-revoke-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("draft")
	}
	if _, err := f.wf.Decide(f.ctx, f.scope, cfg.ID, cfg.Version, "composition-revoke-approve", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	run := processingWorkflowRun(t, f, &cfg, produced, "composition-revoke-run")
	var before int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM files WHERE tenant_id=$1 AND partner_id=$2`, f.scope.Tenant, f.scope.Partner).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokeOutputPolicy(f.ctx, f.scope, input.ID, input.Version, "composition-source-contract-revoke", PolicyDecision{Hash: input.Hash, Version: input.Version, Revision: input.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DescribeProcessingOutput(f.ctx, f.scope, produced.ID, store.OnboardingReference{ID: output.ID, Version: output.Version, Hash: output.Hash}); err == nil {
		t.Fatal("revoked source described as eligible")
	}
	if _, err := f.wf.Work(f.ctx, f.scope, run.ID, "composition-revoked-work"); err == nil {
		t.Fatal("queued composition ignored source revocation")
	}
	var after int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM files WHERE tenant_id=$1 AND partner_id=$2`, f.scope.Tenant, f.scope.Partner).Scan(&after); err != nil || after != before {
		t.Fatal("revoked composition retained a new file", err)
	}
}
