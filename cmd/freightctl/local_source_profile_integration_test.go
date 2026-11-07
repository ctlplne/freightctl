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
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// Extend the original ordinary parser/real PostgreSQL CLI journey. Compilation
// alone does not establish the operator registration or collection outcome.
func qualifyLocalCollectionCLI(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, administrator, reader string, command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "PRIVATE_CLI_PRODUCER")
	configurationDirectory := filepath.Join(t.TempDir(), "configuration")
	for _, p := range []string{directory, configurationDirectory} {
		if err := protectedfs.EnsureDirectory(p); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(configurationDirectory, "source.json")
	if _, err := command(reader, "connection-local-profile", "--local-source-directory", directory, "--output", output); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("ordinary reader prepared a host source", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused profile wrote a public configuration", err)
	}
	raw, err := command(administrator, "connection-local-profile", "--local-source-directory", directory, "--output", output)
	var profile localSourceProfileReceipt
	if err != nil || json.Unmarshal(raw, &profile) != nil || !profile.ReadOnly || profile.Profile != delivery.LocalCollectionProfile || bytes.Contains(raw, []byte(directory)) || bytes.Contains(raw, []byte(output)) {
		t.Fatal("CLI protected profile preparation", err)
	}
	definition := &delivery.LocalCollectionSource{Schema: 1, Reference: output, SHA256: profile.ConfigurationHash, RootFingerprint: profile.RootFingerprint}
	registration := requestFile(workflow.ConnectionRequest{Directory: "/", Local: definition})
	raw, err = command(administrator, "connection-register", "--request-file", registration, "--idempotency-key", "cli-local-registration")
	var result workflow.Result
	var connection workflow.ConnectionView
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &connection) != nil || connection.Local == nil || !connection.Local.ReadOnly || bytes.Contains(raw, []byte(directory)) || bytes.Contains(raw, []byte(output)) {
		t.Fatal("CLI local connection registration", err)
	}
	// The original journey leaves its exact XLSX intake policy active. Collected
	// bytes must pass that ordinary policy and separate release,not bypass it.
	stock := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
	if stock == "" {
		t.Fatal("actual stock XLSX source required for the current intake policy")
	}
	body, err := os.ReadFile(filepath.Join(stock, "shared.xlsx"))
	if err != nil || len(body) == 0 || len(body) > 1<<20 {
		t.Fatal("exact stock XLSX source unavailable", err)
	}
	write := func(name string, body []byte) {
		f, err := protectedfs.CreateExclusive(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err = f.Write(body); err != nil {
			t.Fatal(err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("one.xlsx", body)
	manifest := workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "one.xlsx", Size: int64(len(body)), SHA256: secure.Digest(body)}}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write("one.ready.json", manifestBytes)
	d := workflow.Definition{Schema: 1, Name: "CLI private local collection", Steps: []workflow.Step{}, Source: &workflow.CollectionSource{Kind: "local.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "one.ready.json", Directory: "/", Contract: workflow.CollectionContract, MaxFiles: 1, MaxFile: int64(len(body)), MaxTotal: int64(len(body))}}
	raw, err = command(administrator, "workflow-draft", "--request-file", requestFile(workflow.DraftRequest{Definition: d}), "--idempotency-key", "cli-local-draft")
	var configuration store.Configuration
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &configuration) != nil {
		t.Fatal("CLI local workflow draft", err)
	}
	if _, err = command(administrator, "workflow-approve", "--workflow-id", configuration.ID, "--version", "1", "--definition-hash", configuration.Hash, "--expected-revision", "1", "--idempotency-key", "cli-local-approve"); err != nil {
		t.Fatal("CLI local workflow approval", err)
	}
	identity, err := service.DB.Identity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	selection := workflow.CollectionSelection{Workflow: workflow.Reference{ID: configuration.ID, Version: configuration.Version, Hash: configuration.Hash}, Timeout: 120, Authority: identity.AuthorityRevision}
	raw, err = command(administrator, "workflow-collection-preview", "--request-file", requestFile(selection))
	var preview workflow.CollectionPreview
	if err != nil || json.Unmarshal(raw, &preview) != nil || preview.ExternalContact || preview.Definition.Connection.Local == nil {
		t.Fatal("CLI local collection metadata preview", err)
	}
	raw, err = command(administrator, "workflow-collection-start", "--request-file", requestFile(workflow.CollectionStartRequest{Selection: selection, Hash: preview.Hash}), "--idempotency-key", "cli-local-start")
	var action workflow.CollectionAction
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &action) != nil {
		t.Fatal("CLI local collection start", err)
	}
	workInput := requestFile(workflow.CollectionWorkRequest{Hash: preview.Hash})
	first, err := command(administrator, "workflow-collection-work", "--collection-id", action.ID, "--request-file", workInput, "--idempotency-key", "cli-local-work")
	if err != nil {
		t.Fatal("CLI local collection work", err)
	}
	if err = os.Remove(output); err != nil {
		t.Fatal(err)
	}
	again, err := command(administrator, "workflow-collection-work", "--collection-id", action.ID, "--request-file", workInput, "--idempotency-key", "cli-local-work")
	var original, replayed workflow.Result
	if err != nil || json.Unmarshal(first, &original) != nil || json.Unmarshal(again, &replayed) != nil || !replayed.Replayed || !bytes.Equal(original.Resource, replayed.Resource) {
		t.Fatal("CLI local worker replay reopened private source", err)
	}
	raw, err = command(administrator, "workflow-collection-status", "--collection-id", action.ID)
	var view workflow.CollectionView
	if err != nil || json.Unmarshal(raw, &view) != nil || !view.Job.Captured || len(view.Inputs) != 1 || view.Inputs[0].FileID == nil || view.Inputs[0].RunID != nil || view.BusinessAcceptance != "unknown" {
		t.Fatal("CLI local capture receipt", err)
	}
	fileID := *view.Inputs[0].FileID
	if _, _, err = service.Download(ctx, scope, fileID); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI local capture published unchecked bytes", err)
	}
	if _, _, err = service.DownloadPath(ctx, scope, view.Inputs[0].Target); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("CLI local capture published a held virtual path", err)
	}
	raw, err = command(administrator, "check-status", "--file-id", fileID)
	var checked checks.View
	if err != nil || json.Unmarshal(raw, &checked) != nil || checked.Check == nil || checked.Check.State != "held" || checked.Check.Attempts != 0 || checked.Check.ReportHash != "" {
		t.Fatal("CLI local captured revision inherited a previous check", err)
	}
	if _, err = command(administrator, "check-run", "--file-id", fileID, "--idempotency-key", "cli-local-check"); err != nil {
		t.Fatal("CLI local current XLSX policy check", err)
	}
	raw, err = command(administrator, "check-status", "--file-id", fileID)
	var report checks.Report
	if err != nil || json.Unmarshal(raw, &checked) != nil || checked.Check == nil || !checked.Current || checked.Check.State != "passed" || checked.Check.Attempts != 1 || json.Unmarshal(checked.Check.Report, &report) != nil || report.Engine != "freightctl-xlsx-records-v1" || report.Code != "valid_xlsx_records" || report.Rows != 1 || report.SHA256 != secure.Digest(body) || report.Bytes != int64(len(body)) || report.PolicyHash != checked.Check.PolicyHash {
		t.Fatal("CLI local check lost exact source and current policy binding", err)
	}
	if _, _, err = service.Download(ctx, scope, fileID); !errors.Is(err, store.ErrState) {
		t.Fatal("CLI local check pass bypassed separate release", err)
	}
	release := requestFile(checks.ReleaseDecision{SHA256: secure.Digest(body), PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision})
	if _, err = command(reader, "check-release", "--file-id", fileID, "--request-file", release, "--idempotency-key", "cli-local-reader-release"); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("CLI reader gained local collection release authority", err)
	}
	for i := 0; i < 2; i++ {
		raw, err = command(administrator, "check-release", "--file-id", fileID, "--request-file", release, "--idempotency-key", "cli-local-release")
		var result checks.Result
		if err != nil || json.Unmarshal(raw, &result) != nil || result.Replayed != (i == 1) {
			t.Fatal("CLI local exact separate release or original-key recovery", err)
		}
	}
	file, stream, err := service.DownloadPath(ctx, scope, view.Inputs[0].Target)
	if err != nil {
		t.Fatal("CLI local released virtual path readback", err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, body) || file.ID != *view.Inputs[0].FileID || file.SHA256 != secure.Digest(body) {
		t.Fatal("CLI independent custody readback", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("CLI collector wrote producer state", err)
	}
	for name, want := range map[string][]byte{"one.xlsx": body, "one.ready.json": manifestBytes} {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("CLI collector changed original producer bytes", err)
		}
	}
}
