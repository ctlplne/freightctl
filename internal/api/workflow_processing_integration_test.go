//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingWorkflowHTTPSOrdinaryApprovalRunAndHeldOutput(t *testing.T) {
	processingWorkflowHTTPS(t, false)
}

func TestProducerProjectionHTTPSApprovalRunAndHeldOutputKeepDefaultIngress(t *testing.T) {
	processingWorkflowHTTPS(t, true)
}

func processingWorkflowHTTPS(t *testing.T, producerBound bool) {
	service, manager, admin, server := browserAPI(t, 600*time.Second, custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16})
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	token, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_manage", "workflow_approve", "workflow_execute"})
	actor := store.Scope{Tenant: manager.Tenant, Partner: manager.Partner, TokenHash: secure.Digest(token.Bytes)}
	ctx := context.Background()
	control := &checks.Service{Custody: service}
	policy, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	input, err := control.Register(ctx, manager, "wf-input-policy", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var inputPolicy store.Configuration
	if json.Unmarshal(input.Resource, &inputPolicy) != nil {
		t.Fatal("input policy")
	}
	body := "account\n0001\n"
	source, _, err := service.Accept(ctx, actor, "wf-input", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = control.Run(ctx, actor, source.ID, "wf-check-input"); err != nil {
		t.Fatal(err)
	}
	output := policy
	output.Schema = 2
	output.Kind = "json_records"
	var outputPolicy store.Configuration
	if producerBound {
		registered, err := control.RegisterOutputPolicy(ctx, manager, "wf-producer-output-policy", checks.OutputPolicyRequest{Producer: participant.Actor, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		var contract checks.OutputPolicyRecord
		if json.Unmarshal(registered.Resource, &contract) != nil || contract.Policy == nil {
			t.Fatal("producer output policy")
		}
		outputPolicy = *contract.Policy
		query := "?output_policy_id=" + outputPolicy.ID + "&output_policy_version=1&output_policy_hash=" + outputPolicy.Hash
		_, raw := exchangeAPIRequest(t, server, "GET", prefix+"/checks/"+source.ID+"/processing-contracts"+query, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes)}, nil, 200)
		var described checks.ProcessingContracts
		if json.Unmarshal(raw, &described) != nil || described.Profile != "record-processing-contracts-v2" || described.OutputBinding == nil || described.OutputBinding.Producer.Actor != participant.Actor || described.Source.ID != source.ID || described.OutputPolicy.Reference.ID != outputPolicy.ID {
			t.Fatal("served metadata selection did not bind this producer/source/output")
		}
	} else {
		registered, err := control.Register(ctx, manager, "wf-output-policy", checks.PolicyRequest{ExpectedVersion: 1, Definition: output})
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(registered.Resource, &outputPolicy) != nil {
			t.Fatal("output policy")
		}
	}
	rules, err := checks.NormalizeRecordProjection(policy, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: inputPolicy.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	definition := workflow.Definition{Schema: 3, Name: "Ordinary approved processing", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", Definition: rules, OutputPolicy: workflow.Reference{ID: outputPolicy.ID, Version: outputPolicy.Version, Hash: outputPolicy.Hash}, Reason: "Create a separately held immutable output"}}
	call := func(path, key string, body any) []byte {
		t.Helper()
		headers := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key}
		var raw []byte
		if body != nil {
			raw = exchangeAPIJSON(t, body)
		}
		_, response := exchangeAPIRequest(t, server, "POST", prefix+path, nil, headers, raw, 200)
		return response
	}
	var draft workflow.Result
	if json.Unmarshal(call("/workflows/drafts", "wf-draft", workflow.DraftRequest{Definition: definition}), &draft) != nil {
		t.Fatal("draft envelope")
	}
	var cfg store.Configuration
	if json.Unmarshal(draft.Resource, &cfg) != nil {
		t.Fatal("draft configuration")
	}
	request := workflow.RunRequest{Workflow: workflow.Reference{ID: cfg.ID, Version: cfg.Version, Hash: cfg.Hash}, FileID: source.ID}
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/workflow-runs", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "wf-unapproved"}, exchangeAPIJSON(t, request), 409)
	call("/workflows/"+cfg.ID+"/1/approve", "wf-approve", workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision})
	var created workflow.Result
	if json.Unmarshal(call("/workflow-runs", "wf-run", request), &created) != nil {
		t.Fatal("run envelope")
	}
	var run store.WorkflowRun
	if json.Unmarshal(created.Resource, &run) != nil {
		t.Fatal("run receipt")
	}
	var result workflow.WorkResult
	if json.Unmarshal(call("/workflow-runs/"+run.ID+"/work", "wf-work", nil), &result) != nil || result.Processing == nil || result.Processing.State != "completed" || result.Status.ObservedReason != "output_held" || len(result.Status.Steps) != 0 {
		t.Fatal("served workflow did not use held-output processing")
	}
	if _, _, err = service.Download(ctx, actor, result.Processing.FileID); !errors.Is(err, store.ErrState) {
		t.Fatal("ordinary work request granted release", err)
	}
	var replay workflow.WorkResult
	if json.Unmarshal(call("/workflow-runs/"+run.ID+"/work", "wf-work", nil), &replay) != nil || !replay.Replayed || replay.Processing.ID != result.Processing.ID || replay.Processing.Attempts != 1 {
		t.Fatal("public replay selected a new attempt")
	}
	if producerBound {
		current, err := control.Policy(ctx, manager)
		if err != nil || current.ID != inputPolicy.ID || current.Hash != inputPolicy.Hash || current.Version != inputPolicy.Version || current.State != "active" {
			t.Fatal("served producer task replaced default ingress", err)
		}
	}
}
