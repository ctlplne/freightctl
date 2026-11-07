package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestExchangeParticipantsRequireAccountFenceBeforeCredentialReads(t *testing.T) {
	tx := &Transaction{Scope: Scope{Tenant: secure.NewID(), Partner: secure.NewID()}}
	if err := tx.validateExchangeEndpointParticipants(context.Background(), ExchangeEndpointDefinition{}); !errors.Is(err, ErrIsolation) {
		t.Fatal("unfenced validation reached credential metadata", err)
	}
}

func TestExchangeEndpointCommandsBindMeaningAndRefuseUnsafeRevisions(t *testing.T) {
	definition, _, limits := exchangeContractFixture()
	create := ExchangeEndpointCommand{Operation: "create", ID: "99999999-9999-4999-8999-999999999999", Definition: &definition}
	normalized, hash, err := canonicalExchangeEndpointCommand(create, limits)
	if err != nil || len(hash) != 64 || normalized.Definition == create.Definition {
		t.Fatalf("valid create or independent copy: %v", err)
	}
	changed := create
	changed.Definition = normalized.Definition
	changed.Definition.Recipient.AuthorityRevision++
	_, changedHash, err := canonicalExchangeEndpointCommand(changed, limits)
	if err != nil || changedHash == hash {
		t.Fatal("changed authority did not change request meaning")
	}
	if create.Definition.Recipient.AuthorityRevision == changed.Definition.Recipient.AuthorityRevision {
		t.Fatal("normalization mutated caller-owned definition")
	}
	for _, command := range []ExchangeEndpointCommand{
		{Operation: "activate", ID: create.ID, Definition: &definition},
		{Operation: "create", ID: create.ID, ExpectedRevision: 1, Definition: &definition},
		{Operation: "replace", ID: create.ID, ExpectedRevision: 0, Definition: &definition},
		{Operation: "replace", ID: create.ID, ExpectedRevision: 1},
		{Operation: "replace", ID: create.ID, ExpectedRevision: math.MaxInt64, Definition: &definition},
		{Operation: "revoke", ID: create.ID, ExpectedRevision: 1, Definition: &definition},
		{Operation: "revoke", ID: create.ID, ExpectedRevision: math.MaxInt64},
	} {
		if _, _, err := canonicalExchangeEndpointCommand(command, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatalf("unsafe command accepted: %s revision %d", command.Operation, command.ExpectedRevision)
		}
	}
	if _, _, err := canonicalExchangeEndpointCommand(ExchangeEndpointCommand{Operation: "revoke", ID: create.ID, ExpectedRevision: 1}, ExchangeLimits{}); !errors.Is(err, ErrExchangeInput) {
		t.Fatal("unconfigured limits accepted")
	}
}

func TestExchangeEndpointCommandWireIsStrictAndKeepsCanonicalMeaning(t *testing.T) {
	definition, _, limits := exchangeContractFixture()
	command := ExchangeEndpointCommand{Operation: "create", ID: "99999999-9999-4999-8999-999999999999", Definition: &definition}
	wire, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeExchangeEndpointCommand(wire, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, before, err := canonicalExchangeEndpointCommand(command, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := canonicalExchangeEndpointCommand(*decoded, limits)
	if err != nil || before != after {
		t.Fatal("wire decoding changed command meaning")
	}
	for _, raw := range []string{
		strings.Replace(string(wire), `"operation":"create"`, `"operation":"create","operation":"revoke"`, 1),
		strings.Replace(string(wire), `"operation":"create"`, `"Operation":"create"`, 1),
		strings.Replace(string(wire), `"operation":"create"`, `"operation":"create","approved":true`, 1),
		string(wire) + `{}`,
		`null`,
		strings.Repeat(" ", 24<<10) + string(wire),
	} {
		if _, err := DecodeExchangeEndpointCommand([]byte(raw), limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatal("ambiguous or oversized command wire was accepted")
		}
	}
}
