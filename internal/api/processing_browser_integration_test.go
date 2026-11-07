//go:build integration && jsonbrowser

package api

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingWorkflowNativeBrowserReviewRecoveryAndHeldOutput(t *testing.T) {
	processingWorkflowNativeBrowser(t, false)
}

func TestProducerProcessingNativeBrowserSelectsOutputContractAndKeepsIngress(t *testing.T) {
	processingWorkflowNativeBrowser(t, true)
}

func processingWorkflowNativeBrowser(t *testing.T, producerBound bool) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual Chrome profile requires native GitHub Linux x86_64")
	}
	s, scope, credential, server := browserAPI(t, 600*time.Second)
	control := &checks.Service{Custody: s}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 32, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(t.Context(), scope, "browser-processing-input-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	_ = json.Unmarshal(registered.Resource, &input)
	body := "account,amount,day\n0001,1.01,2026-10-28\n"
	source, _, err := s.Accept(t.Context(), scope, "browser-processing-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(t.Context(), scope, source.ID, "browser-processing-source-check"); err != nil {
		t.Fatal(err)
	}
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	var out store.Configuration
	if producerBound {
		identity, err := s.DB.Identity(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		registered, err = control.RegisterOutputPolicy(t.Context(), scope, "browser-producer-output-policy", checks.OutputPolicyRequest{Producer: identity.Actor, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		var record checks.OutputPolicyRecord
		if json.Unmarshal(registered.Resource, &record) != nil || record.Policy == nil {
			t.Fatal("producer output contract")
		}
		out = *record.Policy
	} else {
		registered, err = control.Register(t.Context(), scope, "browser-processing-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(registered.Resource, &out) != nil {
			t.Fatal("default output contract")
		}
	}
	rules, err := checks.NormalizeRecordProjection(policy, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "amount"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition, err := workflow.Normalize(workflow.Definition{Schema: 3, Name: "Browser settlement processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: out.ID, Version: out.Version, Hash: out.Hash}, TargetPath: "/browser-derived.json", Reason: "Create reviewed settlement records"}})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(definition)
	expected := secure.Digest(wire)
	private, err := os.MkdirTemp("../../.private", "freightctl-processing-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	token, config, result := filepath.Join(private, "credential"), filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	if err = os.WriteFile(token, credential.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(map[string]any{"url": server.URL, "tenant": scope.Tenant, "partner": scope.Partner, "token": token, "source": source.ID, "private": private, "result": result, "hash": expected, "producer_output": producerBound, "output_policy_id": out.ID, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err = os.WriteFile(config, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.CommandContext(t.Context(), "node", "../../scripts/processing-browser.mjs", config)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	raw, err := os.ReadFile(result)
	if err != nil || len(raw) > 4096 {
		t.Fatal("processing browser has no bounded safe result;private evidence retained")
	}
	var summary struct {
		State         string `json:"state"`
		File          string `json:"file"`
		Run           string `json:"run"`
		Hash          string `json:"definition_hash"`
		DraftRequests int    `json:"draft_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
		Inference     bool   `json:"inference_performed"`
		Failure       string `json:"failure_sha256"`
	}
	expectedAccessibility := 5
	if producerBound {
		expectedAccessibility = 6
	}
	if runErr != nil || workflow.Decode(raw, &summary) != nil || summary.State != "passed" || !store.ValidID(summary.File) || !store.ValidID(summary.Run) || summary.Hash != expected || summary.DraftRequests != 2 || summary.Accessibility != expectedAccessibility || summary.Egress != 0 || summary.Errors != 0 || !summary.Sandbox || summary.Inference || summary.Failure != "" {
		t.Fatalf("native processing browser failed;safe result SHA256=%s", secure.Digest(raw))
	}
	wf := &workflow.Service{Custody: s, Processor: control}
	view, err := wf.Status(t.Context(), scope, summary.Run)
	if err != nil || view.Run.State != "succeeded" || view.ObservedReason != "transformed_output_released" || view.Processing.FileID != summary.File || len(view.Steps) != 0 {
		t.Fatal("browser result differs from actual persisted processing/release outcome", err)
	}
	if producerBound {
		current, err := control.Policy(t.Context(), scope)
		if err != nil || current.ID != input.ID || current.Version != input.Version || current.Hash != input.Hash || current.State != "active" {
			t.Fatal("browser producer selection replaced default ingress", err)
		}
	}

}
