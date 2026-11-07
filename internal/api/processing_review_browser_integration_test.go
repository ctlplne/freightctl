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

func TestProcessingReviewNativeBrowserIndependentDecisionRecoveryAndAdoption(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual Chrome profile requires native GitHub Linux x86_64")
	}
	s, manager, _, server := browserAPI(t, 600*time.Second)
	private, err := os.MkdirTemp("../../.private", "freightctl-processing-review-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	makeAccount := func(label string, grants []string) (store.Scope, string, string) {
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
		account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: hash, Policy: &store.AccountPolicy{Label: label, Root: "/", Permissions: grants}}
		if _, err = s.DB.ChangeAccount(t.Context(), manager, "review-browser-"+account.ID, account); err != nil {
			t.Fatal(err)
		}
		return store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: hash}, path, account.ID
	}
	worker, workerToken, _ := makeAccount("Definition creator without approval", []string{"workflow_manage"})
	reviewer, reviewerToken, reviewerID := makeAccount("Definition reviewer without files", []string{"inspect", "workflow_approve"})
	control := &checks.Service{Custody: s}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(t.Context(), manager, "review-browser-input-policy", checks.PolicyRequest{Definition: input})
	if err != nil {
		t.Fatal(err)
	}
	var original store.Configuration
	if json.Unmarshal(registered.Resource, &original) != nil {
		t.Fatal("input policy")
	}
	output := input
	output.Schema = 2
	output.Kind = "json_records"
	registered, err = control.Register(t.Context(), manager, "review-browser-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
	if err != nil {
		t.Fatal(err)
	}
	var policy store.Configuration
	if json.Unmarshal(registered.Resource, &policy) != nil {
		t.Fatal("output policy")
	}
	rules, err := checks.NormalizeRecordProjection(input, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: original.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	wf := &workflow.Service{Custody: s, Processor: control}
	draft, err := wf.Draft(t.Context(), worker, "review-browser-draft", workflow.DraftRequest{Definition: workflow.Definition{Schema: 3, Name: "Browser independent task review", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: policy.ID, Version: policy.Version, Hash: policy.Hash}, Reason: "Review task rules without granting payload access"}}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("draft")
	}
	config, result := filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	encoded, _ := json.Marshal(map[string]any{"url": server.URL, "tenant": manager.Tenant, "partner": manager.Partner, "worker_token": workerToken, "reviewer_token": reviewerToken, "reviewer_id": reviewerID, "workflow": cfg.ID, "workflow_hash": cfg.Hash, "expires_at": time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond), "private": private, "result": result, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err = os.WriteFile(config, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.CommandContext(t.Context(), "node", "../../scripts/processing-review-browser.mjs", config)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	raw, err := os.ReadFile(result)
	if err != nil || len(raw) > 4096 {
		t.Fatal("independent review browser has no bounded safe result;private evidence retained")
	}
	var summary struct {
		State         string `json:"state"`
		Review        string `json:"review"`
		Hash          string `json:"workflow_hash"`
		Requests      int    `json:"proposal_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
		Inference     bool   `json:"inference_performed"`
		Failure       string `json:"failure_sha256"`
		Stage         string `json:"failed_stage"`
	}
	decodeErr := workflow.Decode(raw, &summary)
	if runErr != nil || decodeErr != nil || summary.State != "passed" || !store.ValidID(summary.Review) || summary.Hash != cfg.Hash || summary.Requests != 2 || summary.Accessibility != 7 || summary.Egress != 0 || summary.Errors != 0 || !summary.Sandbox || summary.Inference || summary.Failure != "" || summary.Stage != "" {
		stage := ""
		if decodeErr == nil {
			stage = summary.Stage
		}
		t.Fatalf("native independent review browser failed;stage=%s;safe result SHA256=%s", safeNativeBrowserStage(stage), secure.Digest(raw))
	}
	current, err := wf.ProcessingReview(t.Context(), worker, summary.Review)
	if err != nil || current.State != "withdrawn" || current.Revision != 4 || current.AdoptedRevision != 3 || current.Definition.Workflow.Hash != cfg.Hash || current.Definition.Reviewer.Actor != reviewerID {
		t.Fatal("browser summary differs from persisted review", err)
	}
	if _, err = wf.Configuration(t.Context(), reviewer, cfg.ID, cfg.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("browser review exposed another actor's configuration", err)
	}
	tx, err := s.DB.Begin(t.Context(), worker)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.CheckProcessingReview(t.Context(), cfg.ID, cfg.Version, cfg.Hash)
	if err == nil {
		tx.Tx.Rollback(t.Context())
		t.Fatal("withdrawn browser review supplied current approval")
	}
	var files, reviewEvents, receipts int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM events WHERE resource_id=$1 AND kind='ProcessingWorkflowReviewChanged'),(SELECT count(*) FROM workflow_receipts WHERE resource_id=$1)`, summary.Review).Scan(&files, &reviewEvents, &receipts); err != nil {
		t.Fatal(err)
	}
	tx.Tx.Rollback(t.Context())
	// The reviewer owns its own approval/withdrawal receipts; actor-private RLS
	// leaves only the creator's proposal/adoption receipts visible here.
	if files != 0 || reviewEvents != 4 || receipts != 2 {
		t.Fatal("browser recovery changed artifact/event/owned receipt cardinality")
	}
}
