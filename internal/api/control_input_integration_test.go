//go:build integration

package api

import (
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestNamespaceAndUploadControlAmbiguityCreatesNoDurableState(t *testing.T) {
	s, scope, token, server := browserAPI(t, 600*time.Second)
	cookie, csrf := loginBrowser(t, server, scope, token)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	headers := map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "original-ambiguous-control"}
	snapshot := func() [5]int {
		t.Helper()
		tx, err := s.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(t.Context())
		var out [5]int
		if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_entries),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM upload_sessions),(SELECT count(*) FROM upload_receipts),(SELECT count(*) FROM events)`).Scan(&out[0], &out[1], &out[2], &out[3], &out[4]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	for _, body := range []string{`{"operation":"mkdir","path":"/first","path":"/second"}`, `{"operation":"mkdir","path":"/first","PATH":"/second"}`, "{\"operation\":\"mkdir\",\"path\":\"/a\xff\"}"} {
		exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", cookie, headers, []byte(body), 400)
	}
	for _, body := range []string{`{"path":"/first","path":"/second","expected_size":0,"expected_sha256":"` + secure.Digest(nil) + `"}`, `{"path":"/first","PATH":"/second","expected_size":0,"expected_sha256":"` + secure.Digest(nil) + `"}`, strings.Repeat(" ", 16<<10) + `{}`} {
		exchangeAPIRequest(t, server, "POST", prefix+"/uploads", cookie, headers, []byte(body), 400)
	}
	if snapshot() != before {
		t.Fatal("ambiguous control created namespace,upload,receipt or event state")
	}
	headers["Idempotency-Key"] = "valid-control-directory"
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/commands", cookie, headers, []byte(`{"operation":"mkdir","path":"/valid"}`), 200)
	headers["Idempotency-Key"] = "valid-control-upload"
	exchangeAPIRequest(t, server, "POST", prefix+"/uploads", cookie, headers, []byte(`{"path":"/valid/empty.bin","expected_size":0,"expected_sha256":"`+secure.Digest(nil)+`"}`), 201)
}
