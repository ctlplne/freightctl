//go:build integration && jsonbrowser

package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingProposalNativeBrowserAuthorDisclosureDraftAdoptionAndRecovery(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual Chrome profile requires native GitHub Linux x86_64")
	}
	s, manager, _, server := browserAPI(t, 600*time.Second)
	private, err := os.MkdirTemp("../../.private", "freightctl-processing-proposal-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	account := func(label string, grants []string) (store.Scope, string, string) {
		t.Helper()
		path := filepath.Join(private, secure.NewID()+".token")
		if err := secure.WriteToken(path); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(path, 64)
		if err != nil {
			t.Fatal(err)
		}
		hash := secure.Digest(secret.Bytes)
		secret.Close()
		c := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: hash, Policy: &store.AccountPolicy{Label: label, Root: "/", Permissions: grants}}
		if _, err = s.DB.ChangeAccount(t.Context(), manager, "proposal-browser-"+c.ID, c); err != nil {
			t.Fatal(err)
		}
		return store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: hash}, path, c.ID
	}
	author, authorToken, authorID := account("Definition author without files", []string{"workflow_manage"})
	executor, executorToken, executorID := account("Executor without approval", []string{"workflow_manage", "read", "write", "check_run", "workflow_execute"})
	control := &checks.Service{Custody: s}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	output := input
	output.Schema, output.Kind = 2, "json_records"
	registered, err := control.RegisterOutputPolicy(t.Context(), manager, "proposal-browser-output", checks.OutputPolicyRequest{Producer: executorID, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var contract checks.OutputPolicyRecord
	if json.Unmarshal(registered.Resource, &contract) != nil || contract.Policy == nil {
		t.Fatal("output contract")
	}
	inputRaw, _ := json.Marshal(input)
	rules, err := checks.NormalizeRecordProjection(input, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: secure.Digest(inputRaw), OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition, err := workflow.Normalize(workflow.Definition{Schema: 3, Name: "Browser third-party authored task", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: contract.Policy.ID, Version: contract.Policy.Version, Hash: contract.Policy.Hash}, Reason: "Review private rules before independent draft adoption"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(definition)
	expectedHash := secure.Digest(raw)
	definitionPath := filepath.Join(private, "definition.json")
	if err = os.WriteFile(definitionPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	config, result := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	encoded, _ := json.Marshal(map[string]any{"url": server.URL, "tenant": manager.Tenant, "partner": manager.Partner, "author_token": authorToken, "executor_token": executorToken, "author_id": authorID, "executor_id": executorID, "definition": definitionPath, "workflow_hash": expectedHash, "expires_at": time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond), "private": private, "result": result, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err = os.WriteFile(config, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), "node", "../../scripts/processing-proposal-browser.mjs", config)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	raw, err = os.ReadFile(result)
	if err != nil || len(raw) > 4096 {
		t.Fatal("proposal browser has no bounded safe result;private evidence retained")
	}
	var summary struct {
		State         string `json:"state"`
		Proposal      string `json:"proposal"`
		Workflow      string `json:"workflow"`
		Hash          string `json:"workflow_hash"`
		Requests      int    `json:"proposal_requests"`
		Adoptions     int    `json:"adoption_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
		Inference     bool   `json:"inference_performed"`
		Failure       string `json:"failure_sha256"`
	}
	if runErr != nil || workflow.Decode(raw, &summary) != nil || summary.State != "passed" || !store.ValidID(summary.Proposal) || !store.ValidID(summary.Workflow) || summary.Hash != expectedHash || summary.Requests != 2 || summary.Adoptions != 2 || summary.Accessibility != 6 || summary.Egress != 0 || summary.Errors != 0 || !summary.Sandbox || summary.Inference || summary.Failure != "" {
		t.Fatalf("native proposal browser failed;safe result SHA256=%s", secure.Digest(raw))
	}
	wf := &workflow.Service{Custody: s, Processor: control}
	view, err := wf.ProcessingProposal(t.Context(), executor, summary.Proposal)
	if err != nil || view.Proposal.State != "adopted" || view.Proposal.Revision != 2 || view.Proposal.Adopted == nil || view.Proposal.Adopted.ID != summary.Workflow || view.Proposal.Definition.Author.Actor != authorID {
		t.Fatal("browser summary differs from persisted proposal", err)
	}
	cfg, err := wf.Configuration(t.Context(), executor, summary.Workflow, 1)
	if err != nil || cfg.State != "draft" || cfg.Revision != 1 || cfg.ApprovalAuthority != 0 || cfg.Hash != expectedHash {
		t.Fatal("browser adoption supplied approval or changed rules", err)
	}
	if _, err = wf.Configuration(t.Context(), author, summary.Workflow, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("author gained executor configuration access", err)
	}
	for _, scope := range []store.Scope{author, executor} {
		tx, err := s.DB.BeginApproval(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		var files, events, receipts, runs int
		err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM events WHERE resource_id=$1 AND kind='ProcessingWorkflowProposalChanged'),(SELECT count(*) FROM workflow_receipts WHERE resource_id=$1),(SELECT count(*) FROM workflow_runs)`, summary.Proposal).Scan(&files, &events, &receipts, &runs)
		tx.Tx.Rollback(t.Context())
		if err != nil || files != 0 || events != 2 || receipts != 1 || runs != 0 {
			t.Fatal("browser retry changed owned receipt/event/file/run cardinality", err)
		}
	}
}
