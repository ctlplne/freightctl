//go:build integration

package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestProcessingOutputPolicyHTTPSScopesRegistryAndPreservesDefaultIngress(t *testing.T) {
	s, manager, admin, server := browserAPI(t, 600*time.Second)
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	producer, actor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_execute", "workflow_manage", "workflow_approve"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_execute"})
	control := &checks.Service{Custody: s}
	input, err := checks.Normalize(checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 32}}, MaxBytes: 8192, MaxRows: 4, MaxRecordBytes: 1024, TimeoutSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	registered, err := control.Register(t.Context(), manager, "api-output-default-ingress", checks.PolicyRequest{Definition: input})
	if err != nil {
		t.Fatal(err)
	}
	var before store.Configuration
	if json.Unmarshal(registered.Resource, &before) != nil {
		t.Fatal("ingress")
	}
	output := input
	output.Schema = 2
	output.Kind = "json_records"
	body := exchangeAPIJSON(t, checks.OutputPolicyRequest{Producer: actor.Actor, Definition: output})
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies", cookie, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "api-register-output-policy"}, body, 200)
	var accepted checks.Result
	var record checks.OutputPolicyRecord
	if json.Unmarshal(raw, &accepted) != nil || json.Unmarshal(accepted.Resource, &record) != nil || record.Policy.State != "output_active" || record.Binding.Producer.Actor != actor.Actor || record.IngressChanged || record.Usage != "producer-workflow-output-contract" {
		t.Fatal("output registration incorrectly described its effect")
	}
	id := record.Policy.ID
	headers := map[string]string{"Authorization": "Bearer " + string(producer.Bytes)}
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/processing-output-policies/"+id+"/1", nil, headers, nil, 200)
	var view checks.OutputPolicyView
	if json.Unmarshal(raw, &view) != nil || !view.ProducerCurrent || view.Policy.Hash != record.Policy.Hash {
		t.Fatal("bound producer cannot inspect exact contract")
	}
	_, _ = exchangeAPIRequest(t, server, "GET", prefix+"/processing-output-policies/"+id+"/1", nil, map[string]string{"Authorization": "Bearer " + string(other.Bytes)}, nil, 404)
	rules, err := checks.NormalizeRecordProjection(input, checks.RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: before.Hash, OutputKind: "json_records", Columns: []checks.ProjectionColumn{{Source: "account", Target: "account"}}})
	if err != nil {
		t.Fatal(err)
	}
	task := workflow.Definition{Schema: 3, Name: "Exact selected producer contract", Processing: &workflow.ProcessingTask{ID: "project", Kind: "records.project", OutputPolicy: workflow.Reference{ID: id, Version: 1, Hash: record.Policy.Hash}, Definition: rules, Reason: "Select output contract without changing default ingress"}}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/workflows/drafts", nil, map[string]string{"Authorization": "Bearer " + string(producer.Bytes), "Idempotency-Key": "api-selected-output-task"}, exchangeAPIJSON(t, workflow.DraftRequest{Definition: task}), 200)
	var drafted workflow.Result
	var cfg store.Configuration
	if json.Unmarshal(raw, &drafted) != nil || json.Unmarshal(drafted.Resource, &cfg) != nil {
		t.Fatal("selected output task draft")
	}
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/workflows/"+cfg.ID+"/1/approve", nil, map[string]string{"Authorization": "Bearer " + string(producer.Bytes), "Idempotency-Key": "api-selected-output-approval"}, exchangeAPIJSON(t, workflow.Decision{Hash: cfg.Hash, Revision: cfg.Revision}), 200)
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/processing-workflows", nil, headers, nil, 200)
	var catalog workflow.ProcessingCatalog
	if json.Unmarshal(raw, &catalog) != nil || len(catalog.Workflows) != 1 || !catalog.Workflows[0].ApprovalCurrent || !catalog.Workflows[0].OutputPolicyCurrent {
		t.Fatal("served catalog did not observe exact producer contract independently of approval")
	}
	decision := exchangeAPIJSON(t, checks.PolicyDecision{Hash: record.Policy.Hash, Version: 1, Revision: 1})
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies/"+id+"/1/revoke", nil, map[string]string{"Authorization": "Bearer " + string(producer.Bytes), "Idempotency-Key": "producer-cannot-revoke"}, decision, 403)
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies/"+id+"/1/revoke", cookie, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "api-revoke-output-policy"}, decision, 200)
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/processing-workflows", nil, headers, nil, 200)
	if json.Unmarshal(raw, &catalog) != nil || len(catalog.Workflows) != 1 || !catalog.Workflows[0].ApprovalCurrent || catalog.Workflows[0].OutputPolicyCurrent {
		t.Fatal("served catalog confused old task approval with revoked output policy")
	}
	_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies", cookie, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "api-register-output-policy"}, body, 200)
	var replay checks.Result
	if json.Unmarshal(raw, &replay) != nil || !replay.Replayed {
		t.Fatal("output revocation erased original API registration")
	}
	current, err := control.Policy(t.Context(), manager)
	if err != nil || current.ID != before.ID || current.Version != before.Version || current.Hash != before.Hash || current.State != "active" {
		t.Fatal("API output lifecycle changed ingress", err)
	}
}
