package store

import (
	"errors"
	"math"
	"testing"
)

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
