package store

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExchangeEvidenceOpaqueWireContainsNoSourceReplyOrImmutableEvents(t *testing.T) {
	r := ExchangeTraceRequest{ID: "33333333-3333-4333-8333-333333333333", Direction: "incoming"}
	v := emptyExchangeTrace(Scope{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "22222222-2222-4222-8222-222222222222"}, r, "held", time.Date(2026, 11, 5, 0, 0, 0, 123000, time.UTC))
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(raw, &wire) != nil {
		t.Fatal("wire decode")
	}
	for _, key := range []string{"artifact", "request_hash", "reply_reference_only", "payload", "storage_id", "actor_id"} {
		if _, ok := wire[key]; ok {
			t.Fatal("opaque evidence leaked a source/audit/authority field", key)
		}
	}
	if wire["details"] != "opaque" || wire["storage_verification"] != "not-checked" || wire["retrieval"] != "unknown" || wire["receiver_persistence"] != "unknown" || wire["business_processing"] != "unknown" {
		t.Fatal("opaque evidence claimed a stronger outcome")
	}
	if events, ok := wire["recorded_events"].([]any); !ok || len(events) != 0 {
		t.Fatal("opaque evidence did not use an empty event list")
	}
}
