package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestArtifactExchangeAPIRefusesInventedAuthorityBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	prefix := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"
	for _, route := range []string{"exchange-endpoints/commands", "exchanges", "artifact-ingress/previews"} {
		for _, body := range []string{`{"approved":true}`, `{"sender_actor_id":"33333333-3333-4333-8333-333333333333"}`, `{"url":"https://unapproved.invalid"}`, `{"schema_version":1,"SCHEMA_VERSION":1}`, `null`, strings.Repeat(" ", (24<<10)+1)} {
			r := httptest.NewRequest(http.MethodPost, prefix+route, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("untrusted authority must be rejected before any database access: %s status %d", route, w.Code)
			}
		}
	}
}

func TestExchangeEvidenceRefusesRawEventsScopeAndDirectionSwitchBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchange-traces/previews"
	for _, body := range []string{`{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"incoming","raw_events":true}`, `{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"incoming","tenant_id":"invented"}`, `{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"admin"}`, `{"exchange_id":"33333333-3333-4333-8333-333333333333","direction":"incoming","DIRECTION":"outgoing"}`, `null`, strings.Repeat(" ", 16385)} {
		r := httptest.NewRequest("POST", url, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("trace control reached storage or missing route: %d", w.Code)
		}
	}
}

func TestArtifactExchangeAPIRejectsInvalidReceiveSelectorsBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	prefix := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"
	for _, route := range []string{"exchange-endpoints/not-a-uuid/incoming", "exchange-endpoints/33333333-3333-4333-8333-333333333333/incoming?limit=101", "exchange-endpoints/33333333-3333-4333-8333-333333333333/incoming?after=unapproved"} {
		r := httptest.NewRequest(http.MethodGet, prefix+route, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("invalid selector reached storage: %d", w.Code)
		}
	}
}

func TestArtifactExchangeAPIRefusesMalformedViewIDsBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, suffix := range []string{"", "/file"} {
		r := httptest.NewRequest(http.MethodGet, "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchanges/not-a-uuid"+suffix, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("malformed view ID reached a storage-dependent handler", w.Code)
		}
	}
}

func TestArtifactExchangeAPIUnconfiguredAdapterRefusesWithoutDatabase(t *testing.T) {
	h := New(&custody.Service{}, nil)
	r := httptest.NewRequest(http.MethodGet, "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchanges/33333333-3333-4333-8333-333333333333", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "artifact_exchange_unavailable") {
		t.Fatal("unconfigured exchange adapter did not fail closed", w.Code)
	}
}

func TestExchangeEndpointDirectoryRejectsInvalidSelectorsBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	prefix := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"
	for _, path := range []string{"exchange-endpoints?after=not-an-id", "exchange-endpoints?limit=101", "exchange-endpoints/not-an-id"} {
		r := httptest.NewRequest(http.MethodGet, prefix+path, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("endpoint directory did not refuse malformed selectors before storage", w.Code)
		}
	}
}

func TestExchangeClosureRejectsInventedAuthorityBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	url := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchange-closures"
	for _, body := range []string{`{"operation":"cancel","approved":true}`, `{"schema_version":1,"operation":"cancel","OPERATION":"decline"}`, `null`, `{"operation":"reopen"}`, strings.Repeat(" ", 4097)} {
		r := httptest.NewRequest(http.MethodPost, url, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("closure command reached storage or missing handler: status %d", w.Code)
		}
	}
}

func TestExchangeSourceRejectsMalformedRevisionBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	r := httptest.NewRequest(http.MethodGet, "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/exchange-sources/not-a-revision", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("source selector reached storage or missing handler", w.Code)
	}
}

func TestOutgoingExchangeHistoryRejectsMalformedSelectorsBeforeDatabase(t *testing.T) {
	h := New(&custody.Service{MaxFile: 1024, Exchanges: custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 16, MaxOpenViews: 128, MaxEndpoints: 16}}, nil)
	prefix := "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"
	for _, path := range []string{"outgoing-exchanges?limit=101", "outgoing-exchanges?after=not-a-cursor", "outgoing-exchanges/not-a-view"} {
		r := httptest.NewRequest(http.MethodGet, prefix+path, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("outgoing history selector reached storage or missing handler", w.Code)
		}
	}
}
