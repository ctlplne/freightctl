//go:build integration && jsonbrowser

package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestJSONRecordsNativeBrowserReviewedHashAndReceipt(t *testing.T) {
	structuredNativeBrowser(t, "json_records")
}

func TestFixedWidthNativeBrowserReviewedHashAndReceipt(t *testing.T) {
	structuredNativeBrowser(t, "fixed_width")
}

func TestXMLRecordsNativeBrowserReviewedHashAndReceipt(t *testing.T) {
	structuredNativeBrowser(t, "xml_records")
}

func TestXLSXRecordsNativeBrowserReviewedHashAndReceipt(t *testing.T) {
	structuredNativeBrowser(t, "xlsx_records")
}

func structuredNativeBrowser(t *testing.T, format string) {
	fixed := format == "fixed_width"
	xmlRecords := format == "xml_records"
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("explicit Chrome/PostgreSQL profile requires native GitHub Linux x86_64")
	}
	s, scope, credential, server := browserAPI(t, 600*time.Second)
	t.Cleanup(func() { _ = s.Disk.Close() })
	checking := &checks.Service{Custody: s}
	policy := checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{
		{Name: "account", Type: "text", Required: true},
		{Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2},
		{Name: "day", Type: "date", Required: true},
	}}
	if fixed {
		policy.MaxBytes, policy.MaxRows, policy.MaxRecordBytes, policy.TimeoutSeconds = 1024, 2, 64, 2
		for i, w := range []int{8, 12, 10} {
			policy.Columns[i].MaxBytes = w
		}
	}
	if _, err := checking.Register(t.Context(), scope, "browser-original-csv-policy", checks.PolicyRequest{Definition: policy}); err != nil {
		t.Fatal(err)
	}
	policy.Schema, policy.Kind = 2, "json_records"
	if fixed {
		policy.Schema, policy.Kind = 3, "fixed_width"
		for i, w := range []int{8, 12, 10} {
			policy.Columns[i].Width, policy.Columns[i].Padding = w, "none"
		}
		policy.Columns[1].Padding = "space_left"
	}
	if xmlRecords {
		policy.Schema, policy.Kind = 4, "xml_records"
		policy.XML = &checks.XMLRecordPolicy{Root: "records", Record: "record"}
	}
	if format == "xlsx_records" {
		policy.Schema, policy.Kind = 5, format
		policy.XLSX = &checks.XLSXPolicy{Sheet: "Records", DateMode: "iso_text"}
	}
	definition, err := checks.Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	expected := secure.Digest(wire)
	private, err := os.MkdirTemp("../../.private", "freightctl-json-browser-")
	if err != nil {
		t.Fatal(err)
	}
	private, err = filepath.Abs(private)
	if err != nil {
		t.Fatal(err)
	}
	token, source, config, result := filepath.Join(private, "credential"), filepath.Join(private, "records.json"), filepath.Join(private, "config.json"), filepath.Join(private, "result.json")
	body := []byte("[{\"account\":\"0001\",\"amount\":1.01,\"day\":\"2026-10-28\"}]\n")
	if err = os.WriteFile(token, credential.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	if fixed {
		body = []byte("00000001      100.012026-10-28\r\n")
		if err = os.WriteFile(source, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if xmlRecords {
		body = []byte(xmlRecordsHTTPBody)
		if err = os.WriteFile(source, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if format == "xlsx_records" {
		body = []byte(stockXLSXBody(t, "shared.xlsx"))
		source = filepath.Join(private, "records.xlsx")
		if err = os.WriteFile(source, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	settings := map[string]any{"format": policy.Kind, "url": server.URL, "tenant": scope.Tenant, "partner": scope.Partner, "token": token, "source": source, "private": private, "result": result, "hash": expected, "size": len(body), "sha256": secure.Digest(body), "certificate_der": base64.StdEncoding.EncodeToString(server.Certificate().Raw)}
	encoded, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(config, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.OpenFile(filepath.Join(private, "browser.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.CommandContext(t.Context(), "node", "../../scripts/json-intake-browser.mjs", config)
	command.Stdout, command.Stderr = log, log
	command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
	command.WaitDelay = 5 * time.Second
	runErr := command.Run()
	raw, err := os.ReadFile(result)
	if err != nil || len(raw) > 4096 {
		t.Fatal("native JSON browser has no bounded result;private evidence retained")
	}
	var summary struct {
		State          string `json:"state"`
		File           string `json:"file"`
		PolicyHash     string `json:"policy_hash"`
		PolicyRequests *int   `json:"policy_requests"`
		Accessibility  *int   `json:"accessibility_checks"`
		Egress         *int   `json:"external_egress"`
		Errors         *int   `json:"runtime_errors"`
		Sandbox        *bool  `json:"browser_sandbox"`
		Inference      *bool  `json:"inference_performed"`
		Browser        string `json:"browser_version"`
		Node           string `json:"node_version"`
		Axe            string `json:"axe_version"`
		FailureHash    string `json:"failure_sha256"`
		Stage          string `json:"failed_stage"`
	}
	decodeErr := workflow.Decode(raw, &summary)
	if runErr != nil || decodeErr != nil || summary.State != "passed" || !store.ValidID(summary.File) || summary.PolicyHash != expected || summary.PolicyRequests == nil || *summary.PolicyRequests != 2 || summary.Accessibility == nil || *summary.Accessibility != 5 || summary.Egress == nil || *summary.Egress != 0 || summary.Errors == nil || *summary.Errors != 0 || summary.Sandbox == nil || !*summary.Sandbox || summary.Inference == nil || *summary.Inference || len(summary.Browser) > 80 || !regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`).MatchString(summary.Browser) || summary.Node != "v26.13.0" || summary.Axe != "4.14.0" || summary.FailureHash != "" || summary.Stage != "" {
		stage := ""
		if decodeErr == nil {
			stage = summary.Stage
		}
		t.Fatalf("native JSON browser failed;stage=%s;safe result SHA256=%s", safeNativeBrowserStage(stage), secure.Digest(raw))
	}
	current, err := checking.Policy(t.Context(), scope)
	if err != nil || current == nil || current.Version != 2 || current.Hash != expected || !bytes.Equal(current.Definition, wire) && !jsonRecordsSameJSON(current.Definition, wire) {
		t.Fatal("browser saved a different policy than the reviewed Go definition", err)
	}
	view, err := checking.Get(t.Context(), scope, summary.File)
	if err != nil || view.Check == nil || view.Check.State != "released" || view.Check.Attempts != 1 || view.Check.PolicyHash != expected {
		t.Fatal("browser did not produce one separately released exact JSON check", err)
	}
	file, reader, err := s.DownloadPath(t.Context(), scope, "/browser-records.json")
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(io.LimitReader(reader, int64(len(body)+1)))
	reader.Close()
	if err != nil || file.ID != summary.File || file.Policy != func() string {
		if fixed {
			return store.FixedWidthIntakePrefix
		}
		if xmlRecords {
			return store.XMLRecordsIntakePrefix
		}
		return store.JSONRecordsIntakePrefix
	}()+expected || !bytes.Equal(received, body) {
		t.Fatal("independent Go observer differs from browser-uploaded immutable bytes", err)
	}
	proof, err := s.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer proof.Tx.Rollback(t.Context())
	var policies, receipts, releases, acceptances int
	if err = proof.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM intake_policies),(SELECT count(*) FROM check_receipts WHERE resource_id=$1 AND result->>'version'='2'),(SELECT count(*) FROM file_releases WHERE file_id=$2),(SELECT count(*) FROM events WHERE kind='FileAccepted' AND resource_id=$2)`, current.ID, file.ID).Scan(&policies, &receipts, &releases, &acceptances); err != nil || policies != 2 || receipts != 1 || releases != 1 || acceptances != 1 {
		t.Fatal("browser response-loss replay changed immutable policy/custody cardinality", err, policies, receipts, releases, acceptances)
	}
	t.Logf("native JSON browser exact result SHA256=%s;policy=%s;Chrome=%s", secure.Digest(raw), expected, summary.Browser)
}
