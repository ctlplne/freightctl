package store

import (
	"bytes"
	"encoding/json"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestProcessingAuditKeepsPrivateRulesBindingsAndOriginalKeysBehindExactDigest(t *testing.T) {
	for _, sample := range []struct{ kind, body string }{
		{"ProcessingOutputPolicyBound", `{"binding":{"producer":"private-producer"}}`},
		{"IntakePolicyChanged", `{"state":"output_active","definition":{"columns":["private-rule"]}}`},
		{"CheckCommandCompleted", `{"request_key":"private-key","result":{"profile":"producer-processing-output-policy-v1","binding":{"producer":"private-producer"}}}`},
		{"RecordProjectionChanged", `{"definition":{"plan":{"context":{"namespace_root":"/private-root"}}}}`},
		{"ProcessingWorkflowReviewChanged", `{"definition":{"reviewer":"private-reviewer"}}`},
		{"WorkflowProcessingBound", `{"run_id":"private-run"}`},
		{"WorkflowScheduleChanged", `{"definition":{"processing":{"task":{"name":"private-task"}}}}`},
		{"WorkflowCommandCompleted", `{"request_key":"private-key","result":{"profile":"owned-record-processing-schedule-v1","schedule":{"name":"private-task"}}}`},
		{"WorkflowCommandCompleted", `{"result":{"processing":{"definition":{"private-rule":true}}},"request_key":"private-key"}`},
		{"WorkflowCommandCompleted", `{"result":{"processing_attempt":{"definition":{"plan":{"output_binding":{"private-rule":true}}}}},"request_key":"private-key"}`},
		{"CheckCommandCompleted", `{"result":{"kind":"record_projection","projection":{"private-rule":true}}}`},
		{"FileAccepted", `{"schema_version":6,"record_projection":{"report":{"private-report":true}}}`},
	} {
		raw := json.RawMessage(sample.body)
		e := Event{ID: "event", Kind: sample.kind, ResourceID: "resource", Payload: raw}
		got := redactOnboardingEvent(e)
		var envelope struct {
			Redacted bool   `json:"redacted"`
			Hash     string `json:"source_payload_sha256"`
		}
		if json.Unmarshal(got.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(raw) || bytes.Contains(got.Payload, []byte("private-")) || !bytes.Equal(e.Payload, raw) || got.ID != e.ID || got.Kind != e.Kind || got.ResourceID != e.ResourceID {
			t.Fatal("processing audit disclosed protected payload instead of exact original digest", sample.kind)
		}
	}
	legacy := Event{Kind: "IntakePolicyChanged", Payload: json.RawMessage(`{"state":"active","definition":{"kind":"csv"}}`)}
	if got := redactOnboardingEvent(legacy); !bytes.Equal(got.Payload, legacy.Payload) {
		t.Fatal("ordinary default policy acquired output-private interpretation")
	}
}
