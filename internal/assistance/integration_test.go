//go:build integration

package assistance

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/jackc/pgx/v5/pgconn"
)

type contractPeer struct {
	Server   *httptest.Server
	Requests atomic.Int32
	Output   string
	Hook     func()
}

func peer(t *testing.T, output string) *contractPeer {
	t.Helper()
	p := &contractPeer{Output: output}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.Requests.Add(1)
		if r.URL.Path == "/api/tags" {
			json.NewEncoder(w).Encode(map[string]any{"models": []any{map[string]any{"name": "contract-peer", "digest": strings.Repeat("a", 64)}}})
			return
		}
		var request map[string]any
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid generated request")
		}
		if request["think"] != false || request["stream"] != false || request["keep_alive"] != float64(0) {
			t.Error("unexpected model residency/thinking policy", request)
		}
		prompt, _ := request["prompt"].(string)
		if strings.Contains(prompt, "secret-value") || strings.Contains(prompt, "sensitive.csv") || strings.Contains(prompt, "key_reference") {
			t.Error("private material sent in contract request")
		}
		if p.Hook != nil {
			p.Hook()
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "contract-peer", "response": p.Output, "done": true, "done_reason": "stop", "eval_count": 12, "prompt_eval_count": 80})
	}))
	t.Cleanup(p.Server.Close)
	return p
}
func register(t *testing.T, f *fixture, p *contractPeer, allowText bool) (*Service, *store.Configuration) {
	t.Helper()
	s := &Service{DB: f.wf.Custody.DB}
	result, err := s.Register(f.ctx, f.scope, "profile", ProfileRequest{Definition: Profile{Schema: 1, Endpoint: p.Server.URL, Model: "contract-peer", ModelDigest: strings.Repeat("a", 64), TokenizerDigest: strings.Repeat("b", 64), AllowOperatorText: allowText}})
	if err != nil {
		t.Fatal(err)
	}
	var profile store.Configuration
	if err = json.Unmarshal(result.Resource, &profile); err != nil {
		t.Fatal(err)
	}
	return s, &profile
}
func prepared(t *testing.T, f *fixture, s *Service, p *store.Configuration, kind string, runID string) *store.AIJob {
	t.Helper()
	r := PrepareRequest{Kind: kind, Profile: workflow.Reference{ID: p.ID, Version: p.Version, Hash: p.Hash}, RunID: runID}
	if kind == "propose" {
		r.Name = "reviewed draft"
		r.Requirements = "Send the selected file. password=secret-value"
		r.Destinations = []Destination{{Connection: workflow.Reference{ID: f.connection.ID, Version: 1, Hash: f.connection.Hash}, Filename: "sensitive.csv"}}
	}
	result, err := s.Prepare(f.ctx, f.scope, secure.NewID(), r)
	if err != nil {
		t.Fatal(err)
	}
	var j store.AIJob
	if err = json.Unmarshal(result.Resource, &j); err != nil {
		t.Fatal(err)
	}
	return &j
}
func approve(t *testing.T, f *fixture, s *Service, j *store.AIJob) *store.AIJob {
	t.Helper()
	result, err := s.Approve(f.ctx, f.scope, j.ID, secure.NewID(), Decision{Hash: j.ContextHash, Revision: j.Revision})
	if err != nil {
		t.Fatal(err)
	}
	var approved store.AIJob
	if err = json.Unmarshal(result.Resource, &approved); err != nil {
		t.Fatal(err)
	}
	return &approved
}
func TestAssistanceDisclosureDisabledAndDraftOnlyAdoption(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"status":"ready","order":["d1"],"missing":[]}`)
	s, profile := register(t, f, p, true)
	j := prepared(t, f, s, profile, "propose", "")
	if p.Requests.Load() != 0 || j.State != "prepared" {
		t.Fatal("preparation contacted endpoint")
	}
	if strings.Contains(string(j.Context), "sensitive.csv") || strings.Contains(string(j.Bindings), "secret-value") {
		t.Fatal("recognizable secret persisted or label disclosed")
	}
	aliasRequest := PrepareRequest{Kind: "propose", Name: "redacted labels", Profile: workflow.Reference{ID: profile.ID, Version: 1, Hash: profile.Hash}, Requirements: "send second.csv then first.csv", Destinations: []Destination{{Connection: workflow.Reference{ID: f.connection.ID, Version: 1, Hash: f.connection.Hash}, Filename: "first.csv"}, {Connection: workflow.Reference{ID: f.connection.ID, Version: 1, Hash: f.connection.Hash}, Filename: "second.csv"}}}
	aliasResult, err := s.Prepare(f.ctx, f.scope, "alias-order", aliasRequest)
	if err != nil {
		t.Fatal(err)
	}
	var aliasJob store.AIJob
	if json.Unmarshal(aliasResult.Resource, &aliasJob) != nil {
		t.Fatal("alias context")
	}
	var aliasContext Context
	if json.Unmarshal(aliasJob.Context, &aliasContext) != nil || aliasContext.Requirements != "send d2 then d1" {
		t.Fatal("redaction lost ordering semantics", string(aliasJob.Context))
	}
	var leaked int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE payload::text LIKE '%secret-value%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("unredacted secret entered journal", leaked, err)
	}
	if _, err := s.Approve(f.ctx, f.scope, j.ID, "wrong-hash", Decision{Hash: strings.Repeat("0", 64), Revision: 1}); !errors.Is(err, store.ErrRevision) {
		t.Fatal("wrong context approved", err)
	}
	j = approve(t, f, s, j)
	if _, err := s.Generate(f.ctx, f.scope, j.ID, "disabled"); !errors.Is(err, ErrDisabled) || p.Requests.Load() != 0 {
		t.Fatal("disabled mode contacted endpoint", err, p.Requests.Load())
	}
	s.Enabled = true // Explicitly enable only this tiny synthetic JSON peer, not inference.
	generated, err := s.Generate(f.ctx, f.scope, j.ID, "generate")
	if err != nil {
		t.Fatal(err)
	}
	if generated.Job.State != "succeeded" || generated.Job.Attempts != 1 {
		t.Fatal(generated.Job)
	}
	requestCount := p.Requests.Load()
	replayed, err := s.Generate(f.ctx, f.scope, j.ID, "generate")
	if err != nil || !replayed.Replayed || p.Requests.Load() != requestCount {
		t.Fatal("generation replay repeated disclosure", err)
	}
	// Adoption must roll back the draft and provenance if its command receipt
	// cannot persist. This is a real SQL failure after draft staging.
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_ai_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result->>'state'='draft' THEN RAISE EXCEPTION 'task-owned adoption receipt failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER freightctl_test_ai_receipt_failure BEFORE INSERT ON ai_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_ai_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Adopt(f.ctx, f.scope, j.ID, "failed-adopt", Decision{Hash: j.ContextHash, Revision: generated.Job.Revision}); err == nil {
		t.Fatal("adoption ignored failed receipt")
	}
	var partial int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM workflow_revisions`).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("partial adopted draft retained", partial, err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_ai_receipt_failure ON ai_receipts; DROP FUNCTION freightctl_test_ai_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	adopted, err := s.Adopt(f.ctx, f.scope, j.ID, "adopt", Decision{Hash: j.ContextHash, Revision: generated.Job.Revision})
	if err != nil {
		t.Fatal(err)
	}
	var draft store.Configuration
	if err = json.Unmarshal(adopted.Resource, &draft); err != nil {
		t.Fatal(err)
	}
	if draft.State != "draft" || draft.ApprovalAuthority != 0 {
		t.Fatal("model granted approval", draft)
	}
	var definition workflow.Definition
	if json.Unmarshal(draft.Definition, &definition) != nil || definition.Steps[0].Filename != "sensitive.csv" || definition.Steps[0].Connection.ID != f.connection.ID {
		t.Fatal("binding changed", definition)
	}
	if _, err = s.Adopt(f.ctx, f.scope, j.ID, "adopt", Decision{Hash: j.ContextHash, Revision: generated.Job.Revision}); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"workflow_runs", "delivery_intents"} {
		var n int
		if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatal("adoption executed work", table, n, err)
		}
	}
	// Exact event text cannot bypass immutable profile/context constraints.
	tx, err := s.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	changed := *generated.Job
	changed.Context = json.RawMessage(`{"forged":true}`)
	changed.Revision++
	err = tx.SaveAIJob(f.ctx, &changed, generated.Job.Revision)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("context mutation accepted", err)
	}
	tx.Tx.Rollback(f.ctx)
}
func TestAssistanceRejectsAuthorityAndRecipientInjection(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"status":"ready","order":["outside"],"missing":[],"approved":true}`)
	s, profile := register(t, f, p, true)
	j := approve(t, f, s, prepared(t, f, s, profile, "propose", ""))
	s.Enabled = true
	result, err := s.Generate(f.ctx, f.scope, j.ID, "injected")
	if err != nil {
		t.Fatal(err)
	}
	if result.Job.State != "rejected" || string(result.Job.Result) != "{}" || result.Job.OutputHash == "" {
		t.Fatal("unsafe output not quarantined", result.Job)
	}
	if _, err = s.Adopt(f.ctx, f.scope, j.ID, "unsafe-adopt", Decision{Hash: j.ContextHash, Revision: result.Job.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("injected output adopted", err)
	}
}
func TestAssistanceContextChangeAndProfileRevocationDenyOutput(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"status":"ready","order":["d1"],"missing":[]}`)
	s, profile := register(t, f, p, true)
	j := approve(t, f, s, prepared(t, f, s, profile, "propose", ""))
	s.Enabled = true
	p.Hook = func() {
		_, err := f.wf.RevokeConnection(f.ctx, f.scope, f.connection.ID, 1, "revoke-connection", workflow.Decision{Hash: f.connection.Hash, Revision: 1})
		if err != nil {
			t.Error(err)
		}
	}
	result, err := s.Generate(f.ctx, f.scope, j.ID, "changed-context")
	if err != nil {
		t.Fatal(err)
	}
	if result.Job.State != "superseded" || string(result.Job.Result) != "{}" {
		t.Fatal("stale output accepted", result.Job)
	}
	oldRequests := p.Requests.Load()
	if _, err = s.Generate(f.ctx, f.scope, j.ID, "stale-again"); err == nil || p.Requests.Load() != oldRequests {
		t.Fatal("stale context disclosed again", err)
	}
}
func TestAssistanceDiagnosisCitesActualAuthorizedEvents(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"code":"awaiting_worker","evidence":["e1"],"next_check":"inspect_dispatch"}`)
	s, profile := register(t, f, p, false)
	d := workflow.Definition{Schema: 1, Name: "diagnostic fixture", Steps: []workflow.Step{{ID: "send", Kind: "sftp.deliver", Connection: workflow.Reference{ID: f.connection.ID, Version: 1, Hash: f.connection.Hash}, Filename: "sensitive.csv"}}}
	created, err := f.wf.Draft(f.ctx, f.scope, "draft", workflow.DraftRequest{Definition: d})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(created.Resource, &cfg) != nil {
		t.Fatal("draft result")
	}
	if _, err = f.wf.Decide(f.ctx, f.scope, cfg.ID, 1, "approve", "approve", workflow.Decision{Hash: cfg.Hash, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	runResult, err := f.wf.Run(f.ctx, f.scope, "run", workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: 1, Hash: cfg.Hash}, FileID: f.file.ID})
	if err != nil {
		t.Fatal(err)
	}
	var run store.WorkflowRun
	if json.Unmarshal(runResult.Resource, &run) != nil {
		t.Fatal("run result")
	}
	j := approve(t, f, s, prepared(t, f, s, profile, "diagnose", run.ID))
	s.Enabled = true
	result, err := s.Generate(f.ctx, f.scope, j.ID, "diagnose")
	if err != nil {
		t.Fatal(err)
	}
	var validated ValidatedResult
	if json.Unmarshal(result.Job.Result, &validated) != nil || validated.Diagnosis == nil || len(validated.Citations) != 1 {
		t.Fatal(result.Job)
	}
	citation, err := s.Evidence(f.ctx, f.scope, j.ID, validated.Citations[0].EventID)
	if err != nil || citation.ResourceID != run.ID || citation.Kind != "WorkflowRunChanged" {
		t.Fatal("citation does not resolve", citation, err)
	}
	if _, err = s.Evidence(f.ctx, f.scope, j.ID, secure.NewID()); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("forged citation accessible", err)
	}
	// The endpoint gets only aliases/codes; returned records remain actor scoped.
	token := filepath.Join(t.TempDir(), "other.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := f.scope
	other.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	if _, err = s.Get(f.ctx, other, j.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other actor saw context", err)
	}
	tx, err := s.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	for _, table := range []string{"ai_profiles", "ai_jobs", "ai_receipts"} {
		var n int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil || n != 0 {
			t.Fatal("AI row policy leaked", table, n, err)
		}
	}
}

func TestAssistanceRevokedProfileAndMissingDisclosureGrant(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"status":"ready","order":["d1"],"missing":[]}`)
	s, profile := register(t, f, p, true)
	j := approve(t, f, s, prepared(t, f, s, profile, "propose", ""))
	s.Enabled = true
	if _, err := s.Revoke(f.ctx, f.scope, profile.ID, 1, "revoke-profile", workflow.Decision{Hash: profile.Hash, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Generate(f.ctx, f.scope, j.ID, "revoked-generation"); !errors.Is(err, store.ErrState) || p.Requests.Load() != 0 {
		t.Fatal("revoked profile disclosed context", err)
	}
	// A new profile version uses the same bounded test peer. Dropping disclosure
	// authority does not stop ordinary preparation, but denies its approval.
	r := ProfileRequest{ID: profile.ID, ExpectedVersion: 1}
	if json.Unmarshal(profile.Definition, &r.Definition) != nil {
		t.Fatal("profile fixture")
	}
	result, err := s.Register(f.ctx, f.scope, "profile-v2", r)
	if err != nil {
		t.Fatal(err)
	}
	var p2 store.Configuration
	if json.Unmarshal(result.Resource, &p2) != nil {
		t.Fatal("profile v2")
	}
	id, err := s.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.admin.Exec(f.ctx, `UPDATE credentials SET permissions=array_remove(permissions,'ai_disclose') WHERE tenant_id=$1 AND actor_id=$2`, f.scope.Tenant, id.Actor); err != nil {
		t.Fatal(err)
	}
	fresh := prepared(t, f, s, &p2, "propose", "")
	if _, err = s.Approve(f.ctx, f.scope, fresh.ID, "no-disclosure-grant", Decision{Hash: fresh.ContextHash, Revision: 1}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("text granted its own disclosure", err)
	}
	if p.Requests.Load() != 0 {
		t.Fatal("permission checks contacted peer")
	}
}

func TestAssistanceAdmissionAndFailedAttemptReplayStayBounded(t *testing.T) {
	f := setup(t)
	p := peer(t, `{"status":"ready","order":["d1"],"missing":[]}`)
	s, profile := register(t, f, p, true)
	j := approve(t, f, s, prepared(t, f, s, profile, "propose", ""))
	check, release, err := s.DB.AISlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = check(); err != nil {
		t.Fatal(err)
	}
	// Disabled mode neither consumes nor waits for the one inference slot.
	if _, err = s.Generate(f.ctx, f.scope, j.ID, "disabled-under-load"); !errors.Is(err, ErrDisabled) {
		t.Fatal(err)
	}
	s.Enabled = true
	if _, err = s.Generate(f.ctx, f.scope, j.ID, "busy"); !errors.Is(err, store.ErrLimit) {
		t.Fatal("second global slot admitted", err)
	}
	release()
	p.Server.Close() // Connection failure, not simulated model quality.
	first, err := s.Generate(f.ctx, f.scope, j.ID, "failed-first")
	if err != nil || first.Job.State != "failed" || first.Job.Attempts != 1 {
		t.Fatal(first, err)
	}
	replay, err := s.Generate(f.ctx, f.scope, j.ID, "failed-first")
	if err != nil || !replay.Replayed || replay.Job.Attempts != 1 {
		t.Fatal("same request repeated an attempt", err)
	}
	second, err := s.Generate(f.ctx, f.scope, j.ID, "failed-second")
	if err != nil || second.Job.State != "failed" || second.Job.Attempts != 2 {
		t.Fatal(second, err)
	}
	if _, err = s.Generate(f.ctx, f.scope, j.ID, "failed-third"); !errors.Is(err, store.ErrLimit) {
		t.Fatal("attempt budget exceeded", err)
	}
}
