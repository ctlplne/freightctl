//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

// Append to the original CLI/customer-interface journey, retaining its actual
// PostgreSQL, protected references and ordinary command parser. No model runs.
func qualifyJSONIntakeCLI(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, admin, reader string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	qualifyStructuredIntakeCLI(t, ctx, service, scope, admin, reader, command, requestFile, "json_records")
	qualifyStructuredIntakeCLI(t, ctx, service, scope, admin, reader, command, requestFile, "fixed_width")
	qualifyStructuredIntakeCLI(t, ctx, service, scope, admin, reader, command, requestFile, "xml_records")
	qualifyStructuredIntakeCLI(t, ctx, service, scope, admin, reader, command, requestFile, "xlsx_records")
}

func qualifyStructuredIntakeCLI(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, admin, reader string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string, format string) {
	fixed := format == "fixed_width"
	xmlRecords := format == "xml_records"
	t.Helper()
	policy := checks.Policy{Schema: 2, Kind: "json_records", Columns: []checks.Column{
		{Name: "account", Type: "text", Required: true},
		{Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2},
		{Name: "day", Type: "date", Required: true},
	}}
	keyPrefix, path, prefixPolicy, engine, success, expectedVersion := "cli-json-", "/cli-records.json", store.JSONRecordsIntakePrefix, "freightctl-json-records-v1", "valid_json_records", 0
	if fixed {
		policy.Schema, policy.Kind = 3, "fixed_width"
		for i, w := range []int{8, 12, 10} {
			policy.Columns[i].Width, policy.Columns[i].MaxBytes, policy.Columns[i].Padding = w, w, "none"
		}
		policy.Columns[1].Padding = "space_left"
		keyPrefix, path, prefixPolicy, engine, success, expectedVersion = "cli-fixed-", "/cli-records.fixed", store.FixedWidthIntakePrefix, "freightctl-fixed-width-v1", "valid_fixed_width", 1
	}
	if xmlRecords {
		policy.Schema, policy.Kind = 4, "xml_records"
		policy.XML = &checks.XMLRecordPolicy{Root: "records", Record: "record"}
		keyPrefix, path, prefixPolicy, engine, success, expectedVersion = "cli-xml-", "/cli-records.xml", store.XMLRecordsIntakePrefix, "freightctl-xml-records-v1", "valid_xml_records", 2
	}
	if format == "xlsx_records" {
		policy.Schema, policy.Kind = 5, format
		policy.XLSX = &checks.XLSXPolicy{Sheet: "Records", DateMode: "iso_text"}
		keyPrefix, path, prefixPolicy, engine, success, expectedVersion = "cli-xlsx-", "/cli-records.xlsx", store.XLSXRecordsIntakePrefix, "freightctl-xlsx-records-v1", "valid_xlsx_records", 3
	}
	input := requestFile(checks.PolicyRequest{ExpectedVersion: expectedVersion, Definition: policy})
	raw, err := command(admin, "intake-policy-register", "-request-file", input, "-idempotency-key", keyPrefix+"policy")
	var result checks.Result
	var configured store.Configuration
	if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed || json.Unmarshal(result.Resource, &configured) != nil {
		t.Fatal("CLI JSON policy registration", err)
	}
	definition, err := checks.Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(definition)
	if err != nil || configured.Hash != secure.Digest(wire) {
		t.Fatal("CLI JSON policy changed its reviewed format/hash", err)
	}
	if _, err = command(reader, "intake-policy-register", "-request-file", input, "-idempotency-key", keyPrefix+"readonly-policy"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("CLI reader registered intake policy", err)
	}
	body := []byte("[{\"account\":\"0001\",\"amount\":1.01,\"day\":\"2026-10-28\"}]\n")
	if fixed {
		body = []byte("00000001      100.012026-10-28\r\n")
	}
	if xmlRecords {
		body = []byte(`<records><record><account>0001</account><amount>100.01</amount><day>2026-10-28</day></record></records>`)
	}
	if format == "xlsx_records" {
		root := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
		if root == "" {
			t.Fatal("actual stock XLSX sources required")
		}
		body, err = os.ReadFile(filepath.Join(root, "shared.xlsx"))
		if err != nil {
			t.Fatal(err)
		}
	}
	chunk := filepath.Join(t.TempDir(), "records.json")
	if err = os.WriteFile(chunk, body, 0600); err != nil {
		t.Fatal(err)
	}
	mode := uint32(0600)
	input = requestFile(custody.CreateUpload{Path: path, Size: int64(len(body)), SHA256: secure.Digest(body), Mode: &mode})
	raw, err = command(admin, "upload-create", "-request-file", input, "-idempotency-key", keyPrefix+"create")
	var upload custody.UploadResult
	if err != nil || json.Unmarshal(raw, &upload) != nil || upload.Upload.Offset != 0 || upload.File != nil {
		t.Fatal("CLI resumable JSON creation", err)
	}
	id := upload.Upload.ID
	raw, err = command(admin, "upload-append", "-upload-id", id, "-upload-offset", "0", "-chunk-file", chunk, "-idempotency-key", keyPrefix+"chunk")
	if err != nil || json.Unmarshal(raw, &upload) != nil || upload.Upload.Offset != int64(len(body)) || upload.File != nil {
		t.Fatal("checkpoint was mistaken for durable whole-file acceptance", err)
	}
	raw, err = command(admin, "upload-complete", "-upload-id", id, "-idempotency-key", keyPrefix+"complete")
	if err != nil || json.Unmarshal(raw, &upload) != nil || upload.File == nil || upload.File.Policy != prefixPolicy+configured.Hash || upload.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal("CLI completion did not retain held JSON custody", err)
	}
	file := *upload.File
	if _, _, err = service.Download(ctx, scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI completion published unchecked bytes", err)
	}
	if _, err = command(admin, "check-run", "-file-id", file.ID, "-idempotency-key", keyPrefix+"check"); err != nil {
		t.Fatal(err)
	}
	raw, err = command(admin, "check-run", "-file-id", file.ID, "-idempotency-key", keyPrefix+"check")
	if err != nil || json.Unmarshal(raw, &result) != nil || !result.Replayed {
		t.Fatal("CLI check retry lost the original command", err)
	}
	raw, err = command(admin, "check-status", "-file-id", file.ID)
	var view checks.View
	var report checks.Report
	if err != nil || json.Unmarshal(raw, &view) != nil || view.Check == nil || !view.Current || view.Check.State != "passed" || view.Check.Attempts != 1 || json.Unmarshal(view.Check.Report, &report) != nil || report.Code != success || report.Engine != engine || report.Rows != 1 || report.Bytes != file.Size || report.SHA256 != file.SHA256 || report.PolicyHash != configured.Hash {
		t.Fatal("CLI JSON check status lost its exact evidence", err)
	}
	if _, _, err = service.Download(ctx, scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI check pass bypassed separate approval", err)
	}
	decision := checks.ReleaseDecision{SHA256: file.SHA256, PolicyHash: configured.Hash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}
	input = requestFile(decision)
	if _, err = command(reader, "check-release", "-file-id", file.ID, "-request-file", input, "-idempotency-key", keyPrefix+"readonly-release"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("CLI read permission became release permission", err)
	}
	wrong := decision
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err = command(admin, "check-release", "-file-id", file.ID, "-request-file", requestFile(wrong), "-idempotency-key", keyPrefix+"wrong-release"); !errors.Is(err, store.ErrRevision) {
		t.Fatal("CLI release accepted the wrong revision", err)
	}
	for i := 0; i < 2; i++ {
		raw, err = command(admin, "check-release", "-file-id", file.ID, "-request-file", input, "-idempotency-key", keyPrefix+"release")
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed != (i == 1) {
			t.Fatal("CLI exact release/replay", err)
		}
	}
	actual, received, err := service.DownloadPath(ctx, scope, path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(received, file.Size+1))
	received.Close()
	if err != nil || actual.ID != file.ID || !bytes.Equal(got, body) || secure.Digest(got) != file.SHA256 {
		t.Fatal("independent observer received different CLI JSON bytes", err)
	}
}
