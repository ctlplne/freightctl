//go:build integration

package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingOutputPolicyHTTPSScopesRegistryAndPreservesDefaultIngress(t *testing.T) {
	s, manager, admin, server := browserAPI(t, 600*time.Second)
	cookie, csrf := loginBrowser(t, server, manager, admin)
	prefix := "/v1/tenants/" + manager.Tenant + "/partners/" + manager.Partner
	producer, actor := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "check_run", "workflow_execute"})
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
	if json.Unmarshal(raw, &accepted) != nil || json.Unmarshal(accepted.Resource, &record) != nil || record.Policy.State != "output_active" || record.Binding.Producer.Actor != actor.Actor || record.IngressChanged || record.Usage != "contract-registration-only" {
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
	decision := exchangeAPIJSON(t, checks.PolicyDecision{Hash: record.Policy.Hash, Version: 1, Revision: 1})
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies/"+id+"/1/revoke", nil, map[string]string{"Authorization": "Bearer " + string(producer.Bytes), "Idempotency-Key": "producer-cannot-revoke"}, decision, 403)
	_, _ = exchangeAPIRequest(t, server, "POST", prefix+"/processing-output-policies/"+id+"/1/revoke", cookie, map[string]string{"X-CSRF-Token": csrf, "Idempotency-Key": "api-revoke-output-policy"}, decision, 200)
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
