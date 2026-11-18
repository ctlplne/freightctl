//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func qualifyPortableWorkflowDraft(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, cfg store.Configuration, command func(string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	artifact := filepath.Join(t.TempDir(), "portable-workflow.json")
	raw, err := command("workflow-export", "--output", artifact, "--workflow-id", cfg.ID, "--version", strconv.Itoa(cfg.Version), "--definition-hash", cfg.Hash)
	var receipt workflow.PortableExportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Source.ID != cfg.ID || receipt.Source.Hash != cfg.Hash {
		t.Fatal("ordinary export did not bind the selected workflow", err)
	}
	requireSealedCLIOutput(t, artifact)
	data, err := os.ReadFile(artifact)
	if err != nil || secure.Digest(data) != receipt.SHA256 || len(data) != receipt.Size {
		t.Fatal("published artifact differs from prepared evidence", err)
	}
	var exported workflow.PortableWorkflow
	if json.Unmarshal(data, &exported) != nil || exported.Source != receipt.Source ||
		exported.Profile != workflow.PortableWorkflowProfile || exported.Draft.ID != "" || exported.Draft.ExpectedVersion != 0 ||
		exported.ObservedState != "approved" || len(exported.Dependencies) != 2 || exported.Draft.Definition.Processing == nil {
		t.Fatal("portable workflow changed the source binding or included destination authority")
	}
	processing := exported.Draft.Definition.Processing
	if exported.Dependencies[0].Hash != processing.Definition.SourcePolicyHash || exported.Dependencies[1].ID != processing.OutputPolicy.ID {
		t.Fatal("portable processing dependencies lost their reference")
	}
	raw, err = command("workflow-draft", "--request-file", requestFile(exported.Draft), "--idempotency-key", "portable-workflow-roundtrip")
	var result workflow.Result
	var restored store.Configuration
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &restored) != nil ||
		restored.ID == cfg.ID || restored.Hash != cfg.Hash || restored.State != "draft" || restored.ApprovalAuthority != 0 {
		t.Fatal("ordinary draft re-creation did not preserve definition and approval boundary", err)
	}
	invalid := filepath.Join(t.TempDir(), "wrong-hash.json")
	if raw, err = command("workflow-export", "--output", invalid, "--workflow-id", cfg.ID, "--version", strconv.Itoa(cfg.Version), "--definition-hash", strings.Repeat("0", 64)); !errors.Is(err, store.ErrRevision) || len(raw) != 0 {
		t.Fatal("export accepted a different definition digest", err)
	}
	if _, err := os.Stat(invalid); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed export created an output", err)
	}
	token := filepath.Join(t.TempDir(), "another-workflow-executor.token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := secure.Digest(secret.Bytes)
	secret.Close()
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: fingerprint, Policy: &store.AccountPolicy{
		Label: "Another export actor", Root: "/", Permissions: []string{"workflow_execute"},
	}}
	if _, err := service.DB.ChangeAccount(ctx, scope, "portable-workflow-unrelated-executor", account); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(t.TempDir(), "unrelated.json")
	if raw, err = command("workflow-export", "--token-file", token, "--output", unrelated, "--workflow-id", cfg.ID, "--version", strconv.Itoa(cfg.Version), "--definition-hash", cfg.Hash); !errors.Is(err, store.ErrNotFound) || len(raw) != 0 {
		t.Fatal("another workflow executor obtained this actor's plan", err)
	}
	if _, err := os.Stat(unrelated); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refused actor obtained a plan file", err)
	}
	t.Logf("workflow export SHA-256 %s, definition SHA-256 %s, %d bytes", receipt.SHA256, cfg.Hash, receipt.Size)
}
