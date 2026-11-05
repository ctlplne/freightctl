package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestExchangeClosurePinsExactOfferAndCannotReopenOrClaimAuthority(t *testing.T) {
	c := ExchangeClosureCommand{Schema: 1, ID: "77777777-7777-4777-8777-777777777777", RequestHash: strings.Repeat("a", 64), Operation: "cancel"}
	wire, hash, err := CanonicalExchangeClosure(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExchangeClosure(wire)
	if err != nil || *decoded != c {
		t.Fatal("closure meaning changed", err)
	}
	for _, change := range []func(*ExchangeClosureCommand){
		func(c *ExchangeClosureCommand) { c.RequestHash = strings.Repeat("b", 64) },
		func(c *ExchangeClosureCommand) { c.Operation = "decline" },
		func(c *ExchangeClosureCommand) { c.ID = "88888888-8888-4888-8888-888888888888" },
	} {
		other := c
		change(&other)
		_, different, err := CanonicalExchangeClosure(other)
		if err != nil || hash == different {
			t.Fatal("changed closure meaning reused a command hash", err)
		}
	}
	for _, raw := range [][]byte{
		bytes.Replace(wire, []byte(`"cancel"`), []byte(`"reopen"`), 1),
		bytes.Replace(wire, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
		bytes.Replace(wire, []byte(`"operation":"cancel"`), []byte(`"operation":"cancel","OPERATION":"decline"`), 1),
		bytes.Replace(wire, []byte(`"operation":"cancel"`), []byte(`"operation":"cancel","operation":"cancel"`), 1),
		bytes.Replace(wire, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1),
		bytes.Replace(wire, []byte(`"operation":"cancel"`), []byte(`"operation":"cancel","approved":true`), 1),
		append(append([]byte{}, wire...), []byte(` {}`)...),
		[]byte(strings.Repeat(" ", 4097)),
	} {
		if _, err := DecodeExchangeClosure(raw); !errors.Is(err, ErrExchangeInput) {
			t.Fatal("ambiguous closure or payload authority accepted", err)
		}
	}
	result, err := json.Marshal(ExchangeClosureResult{ID: c.ID, State: "canceled", CommandHash: hash})
	if err != nil || bytes.Contains(result, []byte("artifact")) || bytes.Contains(result, []byte("storage")) || bytes.Contains(result, []byte(c.RequestHash)) {
		t.Fatal("closure receipt disclosed file or storage metadata", err)
	}
}

func TestExchangeClosureAuditRedactsActorPrivateOperationKey(t *testing.T) {
	raw := json.RawMessage(`{"request_key":"private-original-operation","participant":{"actor_id":"private-actor-binding"},"command":{"request_hash":"private-offer-hash"}}`)
	e := Event{ID: "event", Kind: "ArtifactExchangeClosed", ResourceID: "view", Payload: raw}
	redacted := redactOnboardingEvent(e)
	var envelope struct {
		Redacted bool   `json:"redacted"`
		Hash     string `json:"source_payload_sha256"`
	}
	if json.Unmarshal(redacted.Payload, &envelope) != nil || !envelope.Redacted || envelope.Hash != secure.Digest(raw) || bytes.Contains(redacted.Payload, []byte("private-")) || !bytes.Equal(e.Payload, raw) {
		t.Fatal("public audit disclosed actor-private closure command instead of its exact digest")
	}
}
