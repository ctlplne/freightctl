package store

import (
	"errors"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestExchangeEndpointDirectoryRecordsRejectForeignOrMalformedEvidence(t *testing.T) {
	d, _, limits := exchangeContractFixture()
	wire, hash, err := CanonicalExchangeEndpoint(d, limits)
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: d.Recipient.Tenant, Partner: d.Recipient.Partner}
	valid := ExchangeEndpointVersion{ID: secure.NewID(), Revision: 1, Definition: wire, Hash: hash, State: "active", RecordedBy: secure.NewID(), EventID: secure.NewID()}
	if err = validExchangeEndpointRecord(&valid, scope); err != nil {
		t.Fatal(err)
	}
	revoked := valid
	revoked.State = "revoked"
	if err = validExchangeEndpointRecord(&revoked, scope); err != nil {
		t.Fatal("revoked history is not a permission grant", err)
	}
	for _, mutate := range []func(*ExchangeEndpointVersion){
		func(e *ExchangeEndpointVersion) { e.ID = "bad" },
		func(e *ExchangeEndpointVersion) { e.Revision = 0 },
		func(e *ExchangeEndpointVersion) { e.State = "unknown" },
		func(e *ExchangeEndpointVersion) { e.EventID = "" },
		func(e *ExchangeEndpointVersion) { e.RecordedBy = "bad" },
		func(e *ExchangeEndpointVersion) { e.Hash = secure.Digest([]byte("other")) },
		func(e *ExchangeEndpointVersion) {
			e.Definition = append([]byte(" "), wire...)
			e.Hash = secure.Digest(e.Definition)
		},
		func(e *ExchangeEndpointVersion) {
			e.Definition = append(append([]byte{}, wire[:len(wire)-1]...), []byte(`,"schema_version":1}`)...)
			e.Hash = secure.Digest(e.Definition)
		},
	} {
		changed := valid
		mutate(&changed)
		if err = validExchangeEndpointRecord(&changed, scope); !errors.Is(err, ErrIsolation) {
			t.Fatal("invalid endpoint evidence accepted", err)
		}
	}
	wrong := scope
	wrong.Partner = secure.NewID()
	if err = validExchangeEndpointRecord(&valid, wrong); !errors.Is(err, ErrIsolation) {
		t.Fatal("foreign endpoint scope accepted", err)
	}
}
