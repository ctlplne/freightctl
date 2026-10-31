package store

import (
	"bytes"
	"encoding/json"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestWorkflowPlanRedactionCoversDirectAndNestedCommandReceipts(t *testing.T) {
	plan := json.RawMessage(`{"facts":{"source":{"name":"private-producer.csv"}},"selected_steps":["private_recipient"]}`)
	run := map[string]any{"execution_plan": plan}
	for name, event := range map[string]struct {
		kind  string
		value any
	}{
		"projection":     {"WorkflowRunChanged", run},
		"creation":       {"WorkflowCommandCompleted", map[string]any{"result": run}},
		"cancellation":   {"WorkflowCommandCompleted", map[string]any{"result": map[string]any{"run": run}}},
		"status wrapper": {"WorkflowCommandCompleted", map[string]any{"result": map[string]any{"kind": "workflow_run_refresh", "status": map[string]any{"run": run}}}},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := json.Marshal(event.value)
			if err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), payload...)
			e := Event{ID: "original-event", ActorID: "original-actor", ResourceID: "original-run", Kind: event.kind, Payload: payload}
			redacted := redactOnboardingEvent(e)
			var envelope struct {
				Redacted bool   `json:"redacted"`
				Hash     string `json:"source_payload_sha256"`
			}
			if json.Unmarshal(redacted.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(original) || bytes.Contains(redacted.Payload, []byte("private-producer.csv")) || bytes.Contains(redacted.Payload, []byte("private_recipient")) {
				t.Fatal("private source facts or selected recipients escaped their exact digest envelope")
			}
			if redacted.ID != e.ID || redacted.ActorID != e.ActorID || redacted.ResourceID != e.ResourceID || redacted.Kind != e.Kind || !bytes.Equal(e.Payload, original) {
				t.Fatal("redaction changed event identity or the original protected payload")
			}
		})
	}
	legacy := Event{Kind: "WorkflowCommandCompleted", Payload: json.RawMessage(`{"result":{"run":{"id":"legacy-run"},"steps":[]}}`)}
	if result := redactOnboardingEvent(legacy); !bytes.Equal(result.Payload, legacy.Payload) {
		t.Fatal("a legacy result without a plan acquired new redaction behavior")
	}
}

func TestCollectionRoutingAuthorizationAndReceiptsKeepPrivateBindingsInProtectedJournal(t *testing.T) {
	for _, e := range []Event{
		{Kind: "WorkflowCollectionRoutingChanged", Payload: json.RawMessage(`{"definition":{"inputs":[{"input_id":"private-input","file_id":"private-file","plan_hash":"private-plan"}]}}`)},
		{Kind: "WorkflowCommandCompleted", Payload: json.RawMessage(`{"result":{"kind":"workflow_collection_routing","id":"private-authorization","job_id":"private-capture"}}`)},
	} {
		original := append([]byte(nil), e.Payload...)
		redacted := redactOnboardingEvent(e)
		var envelope struct {
			Redacted bool   `json:"redacted"`
			Hash     string `json:"source_payload_sha256"`
		}
		if json.Unmarshal(redacted.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(original) || bytes.Contains(redacted.Payload, []byte("private-")) || !bytes.Equal(e.Payload, original) {
			t.Fatal("routing decision escaped its exact digest envelope or changed the protected payload", e.Kind)
		}
	}
}
