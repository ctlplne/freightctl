package store

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestAuditHistoryBrowserFixtureKeepsOrdinaryFilterAndCursorBinding(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/audit-history.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Reader     Identity            `json:"reader"`
		Request    AuditHistoryRequest `json:"request"`
		Normalized AuditHistoryRequest `json:"normalized"`
		Binding    string              `json:"binding"`
		Cursor     string              `json:"cursor"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("fixture decode")
	}
	r, err := NormalizeAuditHistory(fixture.Request)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := json.Marshal(r)
	expected, _ := json.Marshal(fixture.Normalized)
	if string(actual) != string(expected) {
		t.Fatal("browser/go normalization differs")
	}
	tx := &Transaction{Scope: Scope{Tenant: fixture.Reader.Tenant, Partner: fixture.Reader.Partner}, Actor: fixture.Reader.Actor, AuthorityRevision: fixture.Reader.AuthorityRevision, Root: "/"}
	if auditHistoryBinding(tx, r) != fixture.Binding {
		t.Fatal("browser/go filter binding differs")
	}
	c, err := decodeAuditHistoryCursor(fixture.Cursor)
	if err != nil || c.Binding != fixture.Binding {
		t.Fatal("browser cursor refused", err)
	}
	wire, _ := json.Marshal(c)
	if base64.RawURLEncoding.EncodeToString(wire) != fixture.Cursor {
		t.Fatal("browser/go canonical cursor differs")
	}
}

func TestAuditHistoryCanonicalControlsRefusePayloadRoundingAndUnboundedSelectors(t *testing.T) {
	r, err := DecodeAuditHistory([]byte(`{"limit":2,"kinds":["Zulu","Alpha","Zulu"],"from":"2026-11-05T00:00:00.100000Z","until":"2026-11-06T00:00:00Z"}`))
	if err != nil || strings.Join(r.Kinds, ",") != "Alpha,Zulu" || r.From != "2026-11-05T00:00:00.1Z" {
		t.Fatal("normalization changed filter meaning", err)
	}
	input := AuditHistoryRequest{Limit: 1, Kinds: []string{"Original"}}
	pinned, err := NormalizeAuditHistory(input)
	input.Kinds[0] = "Changed"
	if err != nil || pinned.Kinds[0] != "Original" {
		t.Fatal("caller changed normalized search")
	}
	for _, raw := range []string{`null`, `{"limit":1,"payload":true}`, `{"limit":1,"limit":2}`, `{"limit":1,"LIMIT":2}`, `{"limit":0}`, `{"limit":101}`, `{"limit":1.1}`, `{"limit":1,"actor_id":"invalid"}`, `{"limit":1,"from":"2026-02-30T00:00:00Z"}`, `{"limit":1,"from":"2026-11-05T00:00:00.0000001Z"}`, `{"limit":1,"from":"2026-11-05T00:00:00+00:00"}`, `{"limit":1,"kinds":["bad kind"]}`, `{"limit":1,"after":"bad"}`} {
		if _, err := DecodeAuditHistory([]byte(raw)); err == nil {
			t.Fatal("invalid history selector admitted", raw)
		}
	}
	if _, err := NormalizeAuditHistory(AuditHistoryRequest{Limit: 1, Kinds: make([]string, 17)}); err == nil {
		t.Fatal("unbounded kind alternatives")
	}
}

func TestAuditHistoryCursorBindsFiltersAndCurrentAuthorityWithoutGrant(t *testing.T) {
	tx := &Transaction{Scope: Scope{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "22222222-2222-4222-8222-222222222222"}, Actor: "33333333-3333-4333-8333-333333333333", AuthorityRevision: 1, Root: "/"}
	r, _ := NormalizeAuditHistory(AuditHistoryRequest{Limit: 2, Kinds: []string{"Alpha", "Zulu"}})
	binding := auditHistoryBinding(tx, r)
	resized := r
	resized.Limit = 100
	if auditHistoryBinding(tx, resized) != binding {
		t.Fatal("page size changed original filter identity")
	}
	for _, mutate := range []func(*Transaction){func(v *Transaction) { v.Actor = "44444444-4444-4444-8444-444444444444" }, func(v *Transaction) { v.AuthorityRevision++ }, func(v *Transaction) { v.Root = "/confined" }, func(v *Transaction) { v.Scope.Tenant = "55555555-5555-4555-8555-555555555555" }, func(v *Transaction) { v.Scope.Partner = "66666666-6666-4666-8666-666666666666" }} {
		changed := *tx
		mutate(&changed)
		if auditHistoryBinding(&changed, r) == binding {
			t.Fatal("cursor crossed scope or authority")
		}
	}
	changed := r
	changed.Resource = "77777777-7777-4777-8777-777777777777"
	if auditHistoryBinding(tx, changed) == binding {
		t.Fatal("cursor changed original filter meaning")
	}
	wire, _ := json.Marshal(auditHistoryCursor{At: "2026-11-05T00:00:00.000001Z", ID: "88888888-8888-4888-8888-888888888888", Binding: binding})
	cursor := base64.RawURLEncoding.EncodeToString(wire)
	if parsed, err := decodeAuditHistoryCursor(cursor); err != nil || parsed.Binding != binding {
		t.Fatal("valid keyset cursor refused", err)
	}
	for _, value := range []string{cursor + "\n", cursor + "=", strings.Repeat("a", 1025), base64.RawURLEncoding.EncodeToString([]byte(`{"at":"2026-11-05T00:00:00Z","id":"88888888-8888-4888-8888-888888888888","binding":"` + binding + `","BINDING":"` + binding + `"}`))} {
		if _, err := decodeAuditHistoryCursor(value); err == nil {
			t.Fatal("ambiguous cursor encoding accepted")
		}
	}
}
