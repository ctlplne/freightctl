//go:build integration

package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVCollectionCreationUsesOrdinaryNamespaceAuthorityAndOriginalReceipts(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	headers := map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "dav-mkcol"}
	path := prefix + "/dav/new%20%26%20folder/"
	response, raw := exchangeAPIRequest(t, server, "MKCOL", path, nil, headers, nil, 201)
	var receipt struct {
		Result    store.PathResult `json:"result"`
		Namespace string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.Result.Replayed || receipt.Result.Changed != 1 || receipt.Result.Entry.Path != "/new & folder" || receipt.Result.Entry.Kind != "dir" || receipt.Result.Entry.Revision != 1 || receipt.Namespace != "created-at-commit" || response.Header.Get("Location") != prefix+"/dav/new%20&%20folder/" || response.Header.Get("ETag") != "" {
		t.Fatal("DAV collection creation lost its exact typed namespace receipt")
	}
	entry := receipt.Result.Entry
	exchangeAPIRequest(t, server, "MKCOL", path, nil, headers, nil, 405)
	headers["If-None-Match"] = "*"
	exchangeAPIRequest(t, server, "MKCOL", path, nil, headers, nil, 412)
	delete(headers, "If-None-Match")
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list"})
	denied := map[string]string{"Authorization": "Bearer " + string(reader.Bytes), "Idempotency-Key": "dav-mkcol-denied"}
	exchangeAPIRequest(t, server, "MKCOL", prefix+"/dav/denied/", nil, denied, nil, 403)
	headers["Idempotency-Key"] = "dav-missing-parent"
	exchangeAPIRequest(t, server, "MKCOL", prefix+"/dav/missing/child/", nil, headers, nil, 409)
	exchangeAPIRequest(t, server, "MKCOL", prefix+"/dav/", nil, headers, nil, 405)
	// An ordinary independently authorized namespace command removes the empty
	// directory. Reusing its original DAV key may recover history,never recreate.
	if _, err := service.PathCommand(t.Context(), scope, "dav-mkcol-remove", store.PathCommand{Operation: "rmdir", Path: entry.Path, ExpectedRevision: &entry.Revision}); err != nil {
		t.Fatal(err)
	}
	headers["Idempotency-Key"] = "dav-mkcol"
	response, raw = exchangeAPIRequest(t, server, "MKCOL", path, nil, headers, nil, 200)
	if json.Unmarshal(raw, &receipt) != nil || !receipt.Result.Replayed || receipt.Result.Entry.ID != entry.ID || receipt.Namespace != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
		t.Fatal("historical directory receipt claimed a new namespace effect")
	}
	auth := map[string]string{"Authorization": headers["Authorization"], "Depth": "0"}
	exchangeAPIRequest(t, server, "PROPFIND", path, nil, auth, nil, 404)
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var creates, live, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE kind='PathCreated'),(SELECT count(*) FROM namespace_entries WHERE NOT deleted),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&creates, &live, &intents, &runs); err != nil || creates != 1 || live != 0 || intents != 0 || runs != 0 {
		t.Fatal("DAV directory replay,denial or missing parent created an extra effect", err)
	}
}
