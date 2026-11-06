package store

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestArtifactExchangeBindsLiveEndpointAndExactActor(t *testing.T) {
	d, request, limits := exchangeContractFixture()
	data, hash, err := CanonicalExchangeEndpoint(d, limits)
	if err != nil {
		t.Fatal(err)
	}
	v := &ExchangeEndpointVersion{ID: request.Endpoint.ID, Revision: 1, Hash: hash, Definition: data, State: "active"}
	ref := ExchangeEndpointReference{ID: v.ID, Revision: v.Revision, Hash: v.Hash}
	if _, err = bindExchangeEndpoint(v, ref, limits); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ExchangeEndpointVersion){
		func(e *ExchangeEndpointVersion) { e.State = "revoked" },
		func(e *ExchangeEndpointVersion) { e.Revision++ },
		func(e *ExchangeEndpointVersion) { e.Hash = strings.Repeat("d", 64) },
		func(e *ExchangeEndpointVersion) { e.ID = "77777777-7777-4777-8777-777777777777" },
	} {
		e := *v
		change(&e)
		if _, err = bindExchangeEndpoint(&e, ref, limits); !errors.Is(err, ErrRevision) {
			t.Fatal("changed receive endpoint accepted", err)
		}
	}
	actor := d.Senders[0]
	if _, err = exchangeSender(d, actor); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*ExchangeParticipant){
		func(p *ExchangeParticipant) { p.AuthorityRevision++ },
		func(p *ExchangeParticipant) { p.Partner = d.Recipient.Actor },
		func(p *ExchangeParticipant) { p.Tenant = d.Recipient.Actor },
		func(p *ExchangeParticipant) { p.RootPolicyDigest = strings.Repeat("d", 64) },
		func(p *ExchangeParticipant) { p.Actor = d.Recipient.Actor },
	} {
		p := actor
		change(&p)
		if _, err = exchangeSender(d, p); !errors.Is(err, ErrNotFound) {
			t.Fatal("authority selector granted sender access", err)
		}
	}
}

func TestExistingExchangeEndpointReadDoesNotApplyNewDefinitionAdmissionLimit(t *testing.T) {
	d, r, limits := exchangeContractFixture()
	other := d.Senders[0]
	other.Actor = "99999999-9999-4999-8999-999999999999"
	d.Senders = append(d.Senders, other)
	wire, hash, err := CanonicalExchangeEndpoint(d, limits)
	if err != nil {
		t.Fatal(err)
	}
	v := &ExchangeEndpointVersion{ID: r.Endpoint.ID, Revision: 1, Definition: wire, Hash: hash, State: "active"}
	ref := ExchangeEndpointReference{ID: v.ID, Revision: v.Revision, Hash: v.Hash}
	lower := limits
	lower.MaxSenders = 1
	if _, _, err = CanonicalExchangeEndpoint(d, lower); !errors.Is(err, ErrExchangeInput) {
		t.Fatal("new endpoint admission cap was weakened", err)
	}
	if _, err = bindExchangeEndpoint(v, ref, lower); err != nil {
		t.Fatal("lowering new-definition admission hid an unchanged approved endpoint", err)
	}
}

func TestArtifactExchangePublicResultsExcludeStorageAndWithheldMetadata(t *testing.T) {
	_, request, _ := exchangeContractFixture()
	private := "private-custody-identity-must-not-appear"
	e := ArtifactExchange{ID: "77777777-7777-4777-8777-777777777777", StorageID: private, Request: request}
	for _, result := range []any{ArtifactExchangeResult{Exchange: e}, IncomingExchange{ID: e.ID, State: "offered", Exchange: &e}, ArtifactExchangePage{Exchanges: []IncomingExchange{{ID: e.ID, State: "held"}}}} {
		data, err := json.Marshal(result)
		if err != nil || strings.Contains(string(data), private) {
			t.Fatal("storage identity escaped public result", err)
		}
	}
	data, err := json.Marshal(IncomingExchange{ID: e.ID, State: "held"})
	if err != nil || strings.Contains(string(data), request.Artifact.ID) || strings.Contains(string(data), request.Artifact.SHA256) || strings.Contains(string(data), "exchange") {
		t.Fatal("withheld artifact metadata escaped held state", err)
	}
}

func TestArtifactExchangeNeverFallsBackToOldIntakePolicy(t *testing.T) {
	policy := &Configuration{State: "active", Hash: strings.Repeat("a", 64), Definition: json.RawMessage(`{"schema_version":1,"kind":"csv"}`)}
	jsonPolicy := &Configuration{State: "active", Hash: strings.Repeat("b", 64), Definition: json.RawMessage(`{"schema_version":2,"kind":"json_records"}`)}
	for _, pair := range []struct {
		file    *File
		policy  *Configuration
		allowed bool
	}{
		{&File{Policy: "integrity-only-v1"}, nil, true},
		{&File{Policy: "intake-csv-v1:" + policy.Hash}, policy, true},
		{&File{Policy: "integrity-only-v1"}, policy, false},
		{&File{Policy: "intake-csv-v1:" + strings.Repeat("b", 64)}, policy, false},
		{&File{Policy: "intake-csv-v1:" + policy.Hash}, nil, false},
		{&File{Policy: "intake-csv-v1:" + policy.Hash}, &Configuration{State: "revoked", Hash: policy.Hash, Definition: policy.Definition}, false},
		{&File{Policy: JSONRecordsIntakePrefix + jsonPolicy.Hash}, jsonPolicy, true},
		{&File{Policy: CSVIntakePrefix + jsonPolicy.Hash}, jsonPolicy, false},
		{&File{Policy: JSONRecordsIntakePrefix + policy.Hash}, policy, false},
		{nil, policy, false},
	} {
		if (exchangePolicyCurrent(pair.file, pair.policy) == nil) != pair.allowed {
			t.Fatal("current policy was replaced with historical acceptance")
		}
	}
}
