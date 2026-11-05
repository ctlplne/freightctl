package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func exchangeContractFixture() (ExchangeEndpointDefinition, ExchangeRequest, ExchangeLimits) {
	a := ExchangeParticipant{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "22222222-2222-4222-8222-222222222222", Actor: "33333333-3333-4333-8333-333333333333", AuthorityRevision: 2, RootPolicyDigest: strings.Repeat("a", 64)}
	b := a
	b.Actor = "44444444-4444-4444-8444-444444444444"
	d := ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}
	r := ExchangeRequest{Schema: 1, Artifact: ExchangeArtifact{ID: "55555555-5555-4555-8555-555555555555", Size: 5, SHA256: strings.Repeat("b", 64), Policy: "integrity-only-v1"}, Endpoint: ExchangeEndpointReference{ID: "66666666-6666-4666-8666-666666666666", Revision: 1, Hash: strings.Repeat("c", 64)}, ExpiresAt: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), Receipt: "availability-only-v1"}
	return d, r, ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}
}

func TestExchangeContractCanonicalMeaningAndAdmission(t *testing.T) {
	d, r, limits := exchangeContractFixture()
	data, hash, err := CanonicalExchangeRequest(r, limits)
	if err != nil || len(hash) != 64 {
		t.Fatalf("valid request: %v", err)
	}
	decoded, again, repeated, err := DecodeExchangeRequest(data, limits)
	if err != nil || !bytes.Equal(data, again) || hash != repeated || decoded.Artifact != r.Artifact {
		t.Fatalf("canonical request changed: %v", err)
	}
	if err = r.ValidateAdmission(r.ExpiresAt.Add(-time.Minute), limits); err != nil {
		t.Fatal(err)
	}
	for _, now := range []time.Time{r.ExpiresAt, r.ExpiresAt.Add(time.Second), r.ExpiresAt.Add(-2 * time.Hour)} {
		if !errors.Is(r.ValidateAdmission(now, limits), ErrExchangeInput) {
			t.Fatal("invalid lifetime admitted")
		}
	}
	// Expiry is admission state, not canonical meaning. A replay must still
	// identify its original receipt after expiry; it grants no byte authority.
	if _, _, _, err = DecodeExchangeRequest(data, limits); err != nil {
		t.Fatal(err)
	}
	if _, _, err = CanonicalExchangeEndpoint(d, limits); err != nil {
		t.Fatal(err)
	}
	r.ReplyTo = "77777777-7777-4777-8777-777777777777"
	_, replyHash, err := CanonicalExchangeRequest(r, limits)
	if err != nil || replyHash == hash {
		t.Fatal("reply lineage must bind a new request meaning")
	}
}

func TestExchangeContractRefusesAuthorityInPayloadAndAmbiguousJSON(t *testing.T) {
	_, request, limits := exchangeContractFixture()
	data, _, _ := CanonicalExchangeRequest(request, limits)
	for _, change := range []string{
		`,"sender":{"actor_id":"33333333-3333-4333-8333-333333333333"}`,
		`,"tenant_id":"11111111-1111-4111-8111-111111111111"`,
		`,"url":"https://unapproved.invalid/"`,
		`,"approved":true`, `,"schema_version":1`,
		`,"SCHEMA_VERSION":1`, `,"ſchema_version":1`,
	} {
		malicious := append(append([]byte{}, data[:len(data)-1]...), []byte(change+"}")...)
		if _, _, _, err := DecodeExchangeRequest(malicious, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatalf("untrusted authority or duplicate accepted: %s", change)
		}
	}
	for _, raw := range [][]byte{append(data, data...), []byte(`null`), []byte(`[]`), bytes.Replace(data, []byte(`"size_bytes":5`), []byte(`"size_bytes":null`), 1), bytes.Replace(data, []byte(`"revision":1`), []byte(`"revision":1,"revision":2`), 1), bytes.Repeat([]byte{' '}, (16<<10)+1)} {
		if _, _, _, err := DecodeExchangeRequest(raw, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatal("ambiguous or unbounded request accepted")
		}
	}
}

func TestExchangeContractRejectsChangedArtifactEndpointAndReceiptClaims(t *testing.T) {
	_, valid, limits := exchangeContractFixture()
	mutations := []func(*ExchangeRequest){
		func(r *ExchangeRequest) { r.Schema = 2 },
		func(r *ExchangeRequest) { r.Artifact.ID = "../file" },
		func(r *ExchangeRequest) { r.Artifact.Size = -1 },
		func(r *ExchangeRequest) { r.Artifact.Size = limits.MaxArtifactBytes + 1 },
		func(r *ExchangeRequest) { r.Artifact.SHA256 = strings.Repeat("B", 64) },
		func(r *ExchangeRequest) { r.Artifact.Policy = "clean" },
		func(r *ExchangeRequest) { r.Endpoint.ID = "https://unapproved.invalid" },
		func(r *ExchangeRequest) { r.Endpoint.Revision = 0 },
		func(r *ExchangeRequest) { r.Endpoint.Hash = "latest" },
		func(r *ExchangeRequest) { r.ExpiresAt = time.Time{} },
		func(r *ExchangeRequest) { r.ExpiresAt = r.ExpiresAt.Add(time.Nanosecond) },
		func(r *ExchangeRequest) { r.Receipt = "receiver-durable-acceptance" },
		func(r *ExchangeRequest) { r.Receipt = "business-processed" },
		func(r *ExchangeRequest) { r.ReplyTo = "arbitrary" },
	}
	for i, mutate := range mutations {
		r := valid
		mutate(&r)
		if _, _, err := CanonicalExchangeRequest(r, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatalf("invalid request %d accepted", i)
		}
	}
	// Offset spelling has identical meaning; exact precision is never rounded.
	offset := valid
	offset.ExpiresAt = offset.ExpiresAt.In(time.FixedZone("offset", -5*3600))
	a, _, _ := CanonicalExchangeRequest(valid, limits)
	b, _, err := CanonicalExchangeRequest(offset, limits)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("equivalent expiry instants have different meaning")
	}
}

func TestExchangeEndpointScopesSendersWithoutGrantingAuthority(t *testing.T) {
	valid, _, limits := exchangeContractFixture()
	second := valid.Senders[0]
	second.Actor = "88888888-8888-4888-8888-888888888888"
	valid.Senders = append(valid.Senders, second)
	one, hash, err := CanonicalExchangeEndpoint(valid, limits)
	if err != nil {
		t.Fatal(err)
	}
	decoded, canonical, decodedHash, err := DecodeExchangeEndpoint(one, limits)
	if err != nil || decoded.Recipient != valid.Recipient || !bytes.Equal(one, canonical) || hash != decodedHash {
		t.Fatalf("endpoint decoding changed bindings: %v", err)
	}
	for _, extra := range []string{`,"url":"https://unapproved.invalid"`, `,"PROFILE":"custody-https-poll-v1"`} {
		raw := append(append([]byte{}, one[:len(one)-1]...), []byte(extra+"}")...)
		if _, _, _, err := DecodeExchangeEndpoint(raw, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatal("endpoint authority or alias accepted")
		}
	}
	valid.Senders[0], valid.Senders[1] = valid.Senders[1], valid.Senders[0]
	two, hash2, err := CanonicalExchangeEndpoint(valid, limits)
	if err != nil || !bytes.Equal(one, two) || hash != hash2 {
		t.Fatal("sender-set ordering changed endpoint meaning")
	}
	for _, mutation := range []func(*ExchangeEndpointDefinition){
		func(d *ExchangeEndpointDefinition) { d.Profile = "sftp" },
		func(d *ExchangeEndpointDefinition) { d.Recipient.AuthorityRevision = 0 },
		func(d *ExchangeEndpointDefinition) { d.Recipient.RootPolicyDigest = "unknown" },
		func(d *ExchangeEndpointDefinition) { d.Senders[0].Tenant = "99999999-9999-4999-8999-999999999999" },
		func(d *ExchangeEndpointDefinition) { d.Senders[0].Partner = "99999999-9999-4999-8999-999999999999" },
		func(d *ExchangeEndpointDefinition) { d.Senders = append(d.Senders, d.Senders[0]) },
		func(d *ExchangeEndpointDefinition) { d.Senders = nil },
	} {
		data, _ := json.Marshal(valid)
		var d ExchangeEndpointDefinition
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		mutation(&d)
		if _, _, err = CanonicalExchangeEndpoint(d, limits); !errors.Is(err, ErrExchangeInput) {
			t.Fatal("unqualified or wrong-scope endpoint accepted")
		}
	}
}
