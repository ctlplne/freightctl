package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestOutgoingExchangeStatesNeverUpgradeReceiptEvidence(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		operation                     string
		future, principals, available bool
		want                          string
	}{
		{"", true, true, true, "offered"}, {"", true, true, false, "held"}, {"", true, false, true, "unavailable"},
		{"", false, true, true, "expired"}, {"cancel", false, false, false, "canceled"}, {"decline", true, true, true, "declined"},
	} {
		expires := now
		if c.future {
			expires = now.Add(time.Second)
		}
		state, err := outgoingExchangeState(now, expires, c.operation, c.principals, c.available)
		if err != nil || state != c.want {
			t.Fatal("lifecycle evidence changed meaning", state, err)
		}
	}
	if _, err := outgoingExchangeState(now, now.Add(time.Second), "business-processed", true, true); !errors.Is(err, ErrIsolation) {
		t.Fatal("invented receiver outcome accepted", err)
	}
	_, r, _ := exchangeContractFixture()
	data, err := json.Marshal(OutgoingExchange{Exchange: ArtifactExchange{ID: "77777777-7777-4777-8777-777777777777", Request: r, StorageID: "private-storage-identity"}, Retrieval: "unknown", ReceiverPersistence: "unknown", BusinessProcessing: "unknown"})
	if err != nil || strings.Contains(string(data), "private-storage-identity") {
		t.Fatal("private custody identity escaped history", err)
	}
	for _, fact := range []string{`"retrieval":"unknown"`, `"receiver_persistence":"unknown"`, `"business_processing":"unknown"`} {
		if !strings.Contains(string(data), fact) {
			t.Fatal("stronger receiver outcome was silently inferred")
		}
	}
}
