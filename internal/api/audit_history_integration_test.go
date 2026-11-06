//go:build integration

package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestAuditHistoryHTTPSCookieBearerScopeAndNoPayloadOrMutation(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	identity, err := service.DB.Identity(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	input := store.AuditHistoryRequest{Limit: 1, Actor: identity.Actor}
	counts := func() (int, int) {
		t.Helper()
		tx, err := service.DB.Begin(context.Background(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(context.Background())
		var e, c int
		if err = tx.Tx.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM browser_commands)`).Scan(&e, &c); err != nil {
			t.Fatal(err)
		}
		return e, c
	}
	e0, c0 := counts()
	exchangeAPIRequest(t, server, "POST", prefix+"/audit/history/search", cookie, map[string]string{"Origin": server.URL}, exchangeAPIJSON(t, input), 403)
	_, raw := exchangeAPIRequest(t, server, "POST", prefix+"/audit/history/search", cookie, map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf}, exchangeAPIJSON(t, input), 200)
	var page store.AuditHistoryPage
	if json.Unmarshal(raw, &page) != nil || len(page.Events) != 1 || page.Events[0].Actor != identity.Actor || page.Reader != identity.Actor || page.Payloads != "omitted" || page.Next == "" {
		t.Fatal("cookie metadata search changed authorization/filter")
	}
	for _, forbidden := range []string{string(admin.Bytes), string(reader.Bytes), `"payload":`, `"request_key":`, `"credentials":`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("history leaked protected material")
		}
	}
	_, bearerRaw := exchangeAPIRequest(t, server, "POST", prefix+"/audit/history/search", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, exchangeAPIJSON(t, input), 200)
	var bearer store.AuditHistoryPage
	if json.Unmarshal(bearerRaw, &bearer) != nil || len(bearer.Events) != 1 || bearer.Events[0] != page.Events[0] || bearer.Next != page.Next {
		t.Fatal("cookie/bearer search changed original metadata")
	}
	exchangeAPIRequest(t, server, "POST", prefix+"/audit/history/search", nil, map[string]string{"Authorization": "Bearer " + string(reader.Bytes)}, exchangeAPIJSON(t, input), 403)
	e1, c1 := counts()
	if e0 != e1 || c0 != c1 {
		t.Fatal("search wrote domain or browser command receipts")
	}
}
