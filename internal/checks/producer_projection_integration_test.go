//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func producerProjectionFixture(t *testing.T) (*fixture, *Service, store.Configuration, store.Configuration, *store.File) {
	t.Helper()
	f := setup(t)
	s, input, source := policyAndFile(t, f, goodCSV, true)
	f.wf.Processor = s
	if _, err := s.Run(f.ctx, f.scope, source.ID, "producer-source-check"); err != nil {
		t.Fatal(err)
	}
	identity, err := s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, output := registerOutputFixture(t, f, s, store.AccountCommand{ID: identity.Actor}, *input)
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", MaxBytes: 8192, Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "total"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Reusable producer-bound settlement task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", OutputPolicy: workflow.Reference{ID: output.Policy.ID, Version: output.Policy.Version, Hash: output.Policy.Hash}, Definition: rules, Reason: "Keep CSV ingress while creating separately checked JSON output"}}
	draft, err := f.wf.Draft(f.ctx, f.scope, "producer-task-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("task")
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, cfg.ID, cfg.Version, "producer-task-approve", "approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}); err != nil {
		t.Fatal(err)
	}
	return f, s, cfg, *output.Policy, source
}

func TestProducerProjectionActualRepeatedCSVIngressCreatesSeparatelyCheckedReleasedJSON(t *testing.T) {
	f, s, cfg, output, source := producerProjectionFixture(t)
	var outputs []string
	for i := 0; i < 2; i++ {
		key := "producer-repeat-" + string(rune('a'+i))
		if i > 0 {
			var err error
			source, _, err = s.Custody.AcceptAt(f.ctx, f.scope, key+"-ingress", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/" + key + ".csv"})
			if err != nil {
				t.Fatal("next CSV no longer accepted under default input policy", err)
			}
			if _, err = s.Run(f.ctx, f.scope, source.ID, key+"-input-check"); err != nil {
				t.Fatal(err)
			}
		}
		run := processingWorkflowRun(t, f, &cfg, source, key+"-run")
		worked, err := f.wf.Work(f.ctx, f.scope, run.ID, key+"-work")
		if err != nil || worked.Processing == nil || worked.Processing.State != "completed" || worked.Status.Processing.Released || worked.Status.ObservedReason != "output_held" {
			t.Fatal("producer processing did not commit held output", err)
		}
		id := worked.Processing.FileID
		outputs = append(outputs, id)
		if _, _, err = s.Custody.Download(f.ctx, f.scope, id); !errors.Is(err, store.ErrState) {
			t.Fatal("generated held bytes were readable", err)
		}
		check := getCheck(t, s, f, id)
		if check.PolicyID != output.ID || check.PolicyVersion != output.Version || check.PolicyHash != output.Hash || check.State != "held" || check.Attempts != 0 || check.ReportHash != "" {
			t.Fatal("output did not require fresh checks under exact producer contract")
		}
		if _, err = s.Run(f.ctx, f.scope, id, key+"-output-check"); err != nil {
			t.Fatal(err)
		}
		check = getCheck(t, s, f, id)
		if check.State != "passed" || check.Code != "valid_json_records" {
			t.Fatal("output was checked under incoming CSV policy")
		}
		if _, _, err = s.Custody.Download(f.ctx, f.scope, id); !errors.Is(err, store.ErrState) {
			t.Fatal("check success silently released output", err)
		}
		if _, err = s.Release(f.ctx, f.scope, id, key+"-release", releaseDecision(check)); err != nil {
			t.Fatal(err)
		}
		_, reader, err := s.Custody.Download(f.ctx, f.scope, id)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || !bytes.Contains(data, []byte(`"account":"0001"`)) || !bytes.Contains(data, []byte(`"total":1.01`)) {
			t.Fatal("producer output changed exact identifier/decimal", err)
		}
		if _, err = f.wf.RefreshRun(f.ctx, f.scope, run.ID, key+"-refresh"); err != nil {
			t.Fatal(err)
		}
		view, err := f.wf.Status(f.ctx, f.scope, run.ID)
		if err != nil || view.Run.State != "succeeded" || !view.Processing.Released {
			t.Fatal("explicit release not observed", err)
		}
	}
	if outputs[0] == outputs[1] {
		t.Fatal("separate input revisions reused a custody artifact")
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.State != "active" || current.Version != 1 || current.Hash == output.Hash {
		t.Fatal("reusable processing replaced default ingress", err)
	}
}

func TestProducerProjectionActualRevokedOutputStopsCheckWithoutChangingIngress(t *testing.T) {
	f, s, cfg, output, source := producerProjectionFixture(t)
	run := processingWorkflowRun(t, f, &cfg, source, "producer-revoke-run")
	worked, err := f.wf.Work(f.ctx, f.scope, run.ID, "producer-revoke-work")
	if err != nil || worked.Processing == nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeOutputPolicy(f.ctx, f.scope, output.ID, output.Version, "producer-revoke-policy", PolicyDecision{Hash: output.Hash, Version: output.Version, Revision: output.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Run(f.ctx, f.scope, worked.Processing.FileID, "revoked-output-check"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("revoked output contract permitted a new check", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, worked.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked held output leaked", err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.State != "active" || current.Version != 1 {
		t.Fatal("output revocation changed ingress", err)
	}
}

func TestProducerProjectionActualPublicReleaseStatusDoesNotDiscloseRulesOrGrantBytes(t *testing.T) {
	f, s, cfg, output, source := producerProjectionFixture(t)
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Public status observer", Root: "/", Permissions: []string{"read", "audit_read"}}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "producer-public-observer", account); err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	checkVisibility := func(expected int) {
		t.Helper()
		tx, err := s.Custody.DB.Begin(f.ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var private, public int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM intake_policies WHERE policy_id=$1`, output.ID).Scan(&private); err != nil || private != 0 {
			t.Fatal("public observer read private output rules", err)
		}
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM processing_output_status WHERE policy_id=$1`, output.ID).Scan(&public); err != nil || public != expected {
			t.Fatal("public status did not follow release proof visibility", err)
		}
	}
	checkVisibility(0)
	events, err := s.Custody.DB.Events(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Kind != "ProcessingOutputPolicyBound" {
			continue
		}
		found = true
		var raw []byte
		if err = f.admin.QueryRow(f.ctx, `SELECT payload FROM events WHERE event_id=$1`, event.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var digest struct {
			Redacted bool   `json:"redacted"`
			Hash     string `json:"source_payload_sha256"`
		}
		if json.Unmarshal(event.Payload, &digest) != nil || !digest.Redacted || digest.Hash != secure.Digest(raw) || bytes.Contains(event.Payload, []byte("producer")) || !bytes.Contains(raw, []byte("producer")) {
			t.Fatal("public audit leaked binding or changed protected journal")
		}
	}
	if !found {
		t.Fatal("output producer audit event missing")
	}
	run := processingWorkflowRun(t, f, &cfg, source, "producer-public-run")
	worked, err := f.wf.Work(f.ctx, f.scope, run.ID, "producer-public-work")
	if err != nil || worked.Processing == nil {
		t.Fatal(err)
	}
	id := worked.Processing.FileID
	if _, err = s.Run(f.ctx, f.scope, id, "producer-public-check"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, id, "producer-public-release", releaseDecision(getCheck(t, s, f, id))); err != nil {
		t.Fatal(err)
	}
	checkVisibility(1)
	tx, err := s.Custody.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.FileAvailable(f.ctx, id)
	tx.Tx.Rollback(f.ctx)
	if err != nil {
		t.Fatal("released status required private output rules", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, other, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("public release status granted unauthorized byte access", err)
	}
	if _, err = s.OutputPolicy(f.ctx, other, output.ID, output.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("public release disclosed private output contract", err)
	}
}
