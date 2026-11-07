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
	body := []byte("real CLI local source content\n")
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
	write("one.csv", body)
	manifest := workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}}}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	write("one.ready.json", manifestBytes)
	d := workflow.Definition{Schema: 1, Name: "CLI private local collection", Steps: []workflow.Step{}, Source: &workflow.CollectionSource{Kind: "local.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "one.ready.json", Directory: "/", Contract: workflow.CollectionContract, MaxFiles: 1, MaxFile: 1024, MaxTotal: 1024}}
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
	file, stream, err := service.DownloadPath(ctx, scope, view.Inputs[0].Target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(stream, int64(len(body))+1))
	stream.Close()
	if err != nil || !bytes.Equal(got, body) || file.ID != *view.Inputs[0].FileID || file.SHA256 != secure.Digest(body) {
		t.Fatal("CLI independent custody readback", err)
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 2 {
		t.Fatal("CLI collector wrote producer state", err)
	}
}
