//go:build integration && jsonbrowser

package api

import (
	"encoding/base64"
	"encoding/json"
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

func TestOutputPolicyNativeBrowserAdministratorRecoveryAndRevocationKeepsIngress(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("actual Chrome profile requires native GitHub Linux x86_64")
	}
	s, scope, credential, server := browserAPI(t, 600*time.Second)
	control := &checks.Service{Custody: s}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(t.Context(), scope, "browser-policy-default-input", checks.PolicyRequest{Definition: input})
	if err != nil {
		t.Fatal(err)
	}
	var before store.Configuration
	if json.Unmarshal(registered.Resource, &before) != nil {
		t.Fatal("input policy")
	}
	cookie, csrf := loginBrowser(t, server, scope, credential)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	publisherCredential, publisher := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"admin", "intake_manage"})
	producer, err := s.DB.Identity(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	output := input
	output.Schema, output.Kind = 2, "json_records"
	definition, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.MkdirTemp("../../.private", "freightctl-output-policy-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath, definitionPath, configPath, resultPath := filepath.Join(private, "publisher-credential"), filepath.Join(private, "definition.json"), filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	for path, content := range map[string][]byte{tokenPath: publisherCredential.Bytes, definitionPath: definition} {
		if err = os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, _ := json.Marshal(map[string]any{"url": server.URL, "tenant": scope.Tenant, "partner": scope.Partner, "token": tokenPath, "producer": producer.Actor, "publisher": publisher.Actor, "definition": definitionPath, "definition_hash": secure.Digest(definition), "private": private, "result": resultPath, "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)})
	if err = os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.CommandContext(t.Context(), "node", "../../scripts/output-policy-browser.mjs", configPath)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	raw, err := os.ReadFile(resultPath)
	if err != nil || len(raw) > 4096 {
		t.Fatal("output policy browser has no bounded safe result;private evidence retained")
	}
	var summary struct {
		State         string `json:"state"`
		Policy        string `json:"policy"`
		Registrations int    `json:"registration_requests"`
		Accessibility int    `json:"accessibility_checks"`
		Egress        int    `json:"external_egress"`
		Errors        int    `json:"runtime_errors"`
		Sandbox       bool   `json:"browser_sandbox"`
		Inference     bool   `json:"inference_performed"`
		Failure       string `json:"failure_sha256"`
	}
	if runErr != nil || workflow.Decode(raw, &summary) != nil || summary.State != "passed" || !store.ValidID(summary.Policy) || summary.Registrations != 2 || summary.Accessibility != 4 || summary.Egress != 0 || summary.Errors != 0 || !summary.Sandbox || summary.Inference || summary.Failure != "" {
		t.Fatalf("native output policy browser failed;safe result SHA256=%s", secure.Digest(raw))
	}
	current, err := control.Policy(t.Context(), scope)
	if err != nil || current.ID != before.ID || current.Hash != before.Hash || current.Version != before.Version || current.State != "active" {
		t.Fatal("browser publication/recovery/revocation changed default ingress", err)
	}
	publisherScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(publisherCredential.Bytes)}
	view, err := control.OutputPolicy(t.Context(), publisherScope, summary.Policy, 1)
	if err != nil || view.Policy.State != "output_revoked" || view.Policy.Revision != 2 || view.Binding.Producer.Actor != producer.Actor || view.Binding.Publisher != publisher.Actor || view.Policy.Hash != secure.Digest(definition) {
		t.Fatal("browser outcome differs from actual revoked producer contract", err)
	}
	tx, err := s.DB.Begin(t.Context(), publisherScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var bindings, receipts, files, workflows int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM processing_output_policies WHERE policy_id=$1),(SELECT count(*) FROM check_receipts WHERE actor_id=$2),(SELECT count(*) FROM files),(SELECT count(*) FROM workflow_revisions)`, summary.Policy, publisher.Actor).Scan(&bindings, &receipts, &files, &workflows); err != nil || bindings != 1 || receipts != 2 || files != 0 || workflows != 0 {
		t.Fatal("browser retry duplicated publication or created unrelated product effects", err)
	}
}
