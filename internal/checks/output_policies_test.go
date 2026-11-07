package checks

import (
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingOutputContractPinsProducerAndNeverSelectsDefaultIngress(t *testing.T) {
	d, err := Normalize(testPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, _ := canonical(d)
	scope := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	producer := store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: secure.NewID(), AuthorityRevision: 7, RootPolicyDigest: secure.Digest([]byte("/processor"))}
	policy := &store.Configuration{ID: secure.NewID(), Version: 1, Definition: raw, Hash: hash, State: "output_active", Revision: 1}
	binding, err := outputPolicyBinding(scope, secure.NewID(), policy, producer)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Profile != "producer-processing-output-policy-v1" || binding.PolicyID != policy.ID || binding.Version != policy.Version || binding.Hash != hash || binding.Producer != producer {
		t.Fatal("output policy lost producer/exact contract binding")
	}
	data, _ := json.Marshal(binding)
	for _, forbidden := range []string{"default_ingress", "namespace_root\"", "source_file_id", "release", "execute", "credential"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatal("output contract acquired unrelated authority")
		}
	}
}
func TestProcessingOutputContractRefusesOtherScopeStaleMeaningAndLegacyPolicyState(t *testing.T) {
	d, _ := Normalize(testPolicy(t))
	raw, hash, _ := canonical(d)
	scope := store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	producer := store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: secure.NewID(), AuthorityRevision: 7, RootPolicyDigest: strings.Repeat("a", 64)}
	base := store.Configuration{ID: secure.NewID(), Version: 1, Definition: raw, Hash: hash, State: "output_active", Revision: 1}
	for _, mutate := range []func(*store.Configuration, *store.ExchangeParticipant){
		func(c *store.Configuration, _ *store.ExchangeParticipant) { c.State = "active" },
		func(c *store.Configuration, _ *store.ExchangeParticipant) { c.Hash = strings.Repeat("f", 64) },
		func(_ *store.Configuration, p *store.ExchangeParticipant) { p.Partner = secure.NewID() },
		func(_ *store.Configuration, p *store.ExchangeParticipant) { p.AuthorityRevision = 0 },
		func(_ *store.Configuration, p *store.ExchangeParticipant) { p.RootPolicyDigest = "" },
	} {
		c, p := base, producer
		mutate(&c, &p)
		if _, err := outputPolicyBinding(scope, secure.NewID(), &c, p); err == nil {
			t.Fatal("unsafe output policy scope/meaning accepted")
		}
	}
}
