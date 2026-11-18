//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func readPortableRunHistoryCLI(t *testing.T, request workflow.RunHistorySelection, command func(string, ...string) ([]byte, error), requestFile func(any) string) (workflow.PortableRunHistory, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run-history.json")
	raw, err := command("workflow-run-history-export", "--request-file", requestFile(request), "--output", path)
	var receipt workflow.RunHistoryExportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Source != request {
		t.Fatal("history export receipt", err)
	}
	requireSealedCLIOutput(t, path)
	body, err := os.ReadFile(path)
	var page workflow.PortableRunHistory
	if err != nil || secure.Digest(body) != receipt.SHA256 || len(body) != receipt.Size || json.Unmarshal(body, &page) != nil {
		t.Fatal("protected artifact changed after preparation", err)
	}
	return page, body
}

func qualifyPortableRunHistory(t *testing.T, ctx context.Context, service *custody.Service, scope store.Scope, live workflow.RunView, pinned workflow.RunHistorySelection, before []byte,
	command func(string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	if live.Run == nil || live.Run.Revision < 3 || live.Run.State != "succeeded" {
		t.Fatal("expected a real committed processing lifecycle")
	}
	actor, err := service.DB.Identity(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	selection := workflow.RunHistorySelection{RunID: live.Run.ID, WorkflowHash: live.Run.WorkflowHash, ThroughRevision: live.Run.Revision, Limit: 1}
	export := func(request workflow.RunHistorySelection) (workflow.PortableRunHistory, []byte) {
		t.Helper()
		page, body := readPortableRunHistoryCLI(t, request, command, requestFile)
		if page.Profile != workflow.PortableRunHistoryProfile || page.SourceActor != actor.Actor || page.SourceTenant != scope.Tenant || page.SourcePartner != scope.Partner ||
			page.Selection != request || page.File != live.Run.Source || page.Workflow.Hash != live.Run.WorkflowHash || page.Workflow.ID != live.Run.WorkflowID ||
			bytes.Contains(body, []byte(`"execution_plan"`)) || bytes.Contains(body, []byte(`"storage_id"`)) {
			t.Fatal("export returned mismatched scope, pinned meaning, or private execution detail")
		}
		return page, body
	}
	_, later := export(pinned)
	if !bytes.Equal(before, later) {
		t.Fatal("committing later run states changed a pinned historical page")
	}
	first, firstBytes := export(selection)
	if len(first.Transitions) != 1 || first.Transitions[0].Revision != 1 || first.Transitions[0].State != "queued" ||
		first.NextAfterRevision == nil || *first.NextAfterRevision != 1 {
		t.Fatal("head status replaced original transition or initial cursor")
	}
	_, replay := export(selection)
	if !bytes.Equal(replay, firstBytes) {
		t.Fatal("same historical window produced different bytes")
	}
	selection.AfterRevision = *first.NextAfterRevision
	selection.Limit = store.MaxWorkflowRunHistoryPage
	tail, tailBytes := export(selection)
	count := int64(len(tail.Transitions))
	if count != live.Run.Revision-1 || tail.NextAfterRevision != nil {
		t.Fatal("lost transactions while advancing cursor")
	}
	for index, event := range tail.Transitions {
		if event.Revision != int64(index)+2 || !store.ValidID(event.EventID) || event.At.IsZero() || event.At.Location().String() != "UTC" {
			t.Fatal("incorrect immutable event ordering or timestamp")
		}
	}
	head := tail.Transitions[len(tail.Transitions)-1]
	if head.State != live.Run.State || head.Reason != live.Run.Reason || head.EventID == first.Transitions[0].EventID {
		t.Fatal("final export row lost exact committed run result")
	}
	refuse := func(request workflow.RunHistorySelection, want error, extra ...string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "refused.json")
		flags := append([]string{"--request-file", requestFile(request), "--output", path}, extra...)
		if body, err := command("workflow-run-history-export", flags...); !errors.Is(err, want) || len(body) != 0 {
			t.Fatal("invalid or unrelated request exported a page", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused export exposed an artifact", err)
		}
	}
	wrong := selection
	wrong.WorkflowHash = strings.Repeat("0", 64)
	refuse(wrong, store.ErrRevision)
	wrong = selection
	wrong.ThroughRevision++
	refuse(wrong, store.ErrRevision)
	wrong = selection
	wrong.AfterRevision = wrong.ThroughRevision
	refuse(wrong, workflow.ErrInput)
	token := filepath.Join(t.TempDir(), "unrelated-run-reader.token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := secure.Digest(secret.Bytes)
	secret.Close()
	unrelated := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: hash, Policy: &store.AccountPolicy{
		Label: "Unrelated workflow reader", Root: "/", Permissions: []string{"read", "workflow_execute"},
	}}
	if _, err = service.DB.ChangeAccount(ctx, scope, "portable-run-separate-reader", unrelated); err != nil {
		t.Fatal(err)
	}
	refuse(selection, store.ErrNotFound, "--token-file", token)
	var after workflow.RunView
	result, err := command("workflow-run-status", "--run-id", live.Run.ID)
	if err != nil || json.Unmarshal(result, &after) != nil || after.Run == nil || after.Run.Revision != live.Run.Revision ||
		after.Run.State != live.Run.State || after.ObservedReason != live.ObservedReason {
		t.Fatal("history export changed the workflow run", err)
	}
	t.Logf("run transition count %d, pinned queued page %s, initial page %s, final page %s", live.Run.Revision, secure.Digest(before), secure.Digest(firstBytes), secure.Digest(tailBytes))
}
