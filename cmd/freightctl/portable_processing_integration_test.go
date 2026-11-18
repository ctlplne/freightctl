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
	"strconv"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func qualifyReboundPortableProcessing(t *testing.T, ctx context.Context, service *custody.Service, source, destination store.Scope,
	sourceWorkflow store.Configuration, destinationOutput workflow.Reference, intakeHash, inputFile, originalOutput string,
	destinationFlags []string, command func(string, ...string) ([]byte, error), requestFile func(any) string) workflow.Reference {
	t.Helper()
	archive := filepath.Join(privateCLIDirectory(t), "workflow.json")
	raw, err := command("workflow-export", "--workflow-id", sourceWorkflow.ID, "--version", strconv.Itoa(sourceWorkflow.Version),
		"--definition-hash", sourceWorkflow.Hash, "--output", archive)
	var receipt workflow.PortableExportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("export approved source revision", err)
	}
	artifact, err := os.ReadFile(archive)
	var portable workflow.PortableWorkflow
	if err != nil || secure.Digest(artifact) != receipt.SHA256 || json.Unmarshal(artifact, &portable) != nil ||
		portable.Draft.Definition.Processing == nil || portable.Draft.Definition.Processing.Definition.SourcePolicyHash != intakeHash {
		t.Fatal("moved intake policy did not preserve the exact source contract", err)
	}
	processing := portable.Draft.Definition.Processing
	if processing.OutputPolicy.ID == destinationOutput.ID || processing.OutputPolicy.Hash != destinationOutput.Hash {
		t.Fatal("destination output must be a separate registration of the same rules")
	}
	processing.OutputPolicy = destinationOutput
	runInDestination := func(name string, extra ...string) ([]byte, error) {
		flags := append(append([]string{}, destinationFlags...), extra...)
		return command(name, flags...)
	}
	raw, err = runInDestination("workflow-draft", "--request-file", requestFile(portable.Draft), "--idempotency-key", "portable-processing-draft")
	var result workflow.Result
	var newWorkflow store.Configuration
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &newWorkflow) != nil ||
		newWorkflow.State != "draft" || newWorkflow.ID == sourceWorkflow.ID || newWorkflow.Hash == sourceWorkflow.Hash || newWorkflow.ApprovalAuthority != 0 {
		t.Fatal("rebinding preserved source runtime authority or missed the new dependency", err)
	}
	ref := workflow.Reference{ID: newWorkflow.ID, Version: newWorkflow.Version, Hash: newWorkflow.Hash}
	request := requestFile(workflow.RunRequest{Workflow: ref, FileID: inputFile})
	if _, err = runInDestination("workflow-run", "--request-file", request, "--idempotency-key", "portable-processing-unapproved"); !errors.Is(err, store.ErrState) {
		t.Fatal("moved workflow ran without separate destination approval", err)
	}
	if _, err = runInDestination("workflow-approve", "--workflow-id", ref.ID, "--version", strconv.Itoa(ref.Version),
		"--definition-hash", ref.Hash, "--expected-revision", "1", "--idempotency-key", "portable-processing-approve"); err != nil {
		t.Fatal("destination ordinary approval", err)
	}
	raw, err = runInDestination("workflow-run", "--request-file", request, "--idempotency-key", "portable-processing-run")
	var workRun store.WorkflowRun
	if err != nil || json.Unmarshal(raw, &result) != nil || json.Unmarshal(result.Resource, &workRun) != nil {
		t.Fatal("run destination workflow against new intake", err)
	}
	raw, err = runInDestination("workflow-work", "--run-id", workRun.ID, "--idempotency-key", "portable-processing-work")
	var work workflow.WorkResult
	if err != nil || json.Unmarshal(raw, &work) != nil || work.Processing == nil || work.Status.ObservedReason != "output_held" {
		t.Fatal("destination processing missed ordinary output hold", err)
	}
	output := work.Processing.FileID
	if output == originalOutput {
		t.Fatal("destination reused a source file identity")
	}
	if _, _, err = service.Download(ctx, destination, output); !errors.Is(err, store.ErrState) {
		t.Fatal("moved workflow inherited output release", err)
	}
	control := &checks.Service{Custody: service}
	if _, err = control.Run(ctx, destination, output, "portable-processing-check"); err != nil {
		t.Fatal("destination output checks", err)
	}
	view, err := control.Get(ctx, destination, output)
	var binding store.CheckBinding
	if err != nil || view.Check == nil || view.Check.PolicyID != destinationOutput.ID || view.Check.PolicyHash != destinationOutput.Hash ||
		view.Check.State != "passed" || json.Unmarshal(view.Check.Binding, &binding) != nil {
		t.Fatal("moved workflow used a different output contract", err)
	}
	release := checks.ReleaseDecision{SHA256: binding.File.SHA256, PolicyHash: view.Check.PolicyHash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}
	if _, err = control.Release(ctx, destination, output, "portable-processing-release", release); err != nil {
		t.Fatal("separate destination output release", err)
	}
	read := func(scope store.Scope, file string) []byte {
		t.Helper()
		_, reader, err := service.Download(ctx, scope, file)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		content, err := io.ReadAll(io.LimitReader(reader, 1024))
		if err != nil || len(content) == 0 || len(content) >= 1024 {
			t.Fatal("unexpected fixture output", err)
		}
		return content
	}
	expected, actual := read(source, originalOutput), read(destination, output)
	if !bytes.Equal(expected, actual) {
		t.Fatal("moved workflow changed the bytes received through ordinary custody")
	}
	if _, err = runInDestination("workflow-refresh", "--run-id", workRun.ID, "--idempotency-key", "portable-processing-refresh"); err != nil {
		t.Fatal("destination original workflow refresh", err)
	}
	raw, err = runInDestination("workflow-run-status", "--run-id", workRun.ID)
	var status workflow.RunView
	if err != nil || json.Unmarshal(raw, &status) != nil || status.ObservedState != "succeeded" || status.ObservedReason != "transformed_output_released" {
		t.Fatal("destination workflow missed separately released outcome", err)
	}
	t.Logf("source archive %s, rebound definition %s, equal released output %s", receipt.SHA256, newWorkflow.Hash, secure.Digest(actual))
	return ref
}
