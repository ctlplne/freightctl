//go:build integration

package api

import (
	"encoding/json"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"testing"
	"time"
)

func TestAccountAPIUsesBrowserCSRFStrictInputAndCurrentPolicy(t *testing.T) {
	_, scope, credential, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, credential)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	command := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic-api-credential")), Policy: &store.AccountPolicy{Label: "API account", Root: "/", Permissions: []string{"read"}}}
	body, _ := json.Marshal(command)
	headers := map[string]string{"Origin": server.URL, "Idempotency-Key": "api-account"}
	browserRequest(t, server, "POST", prefix+"/accounts/commands", cookie, headers, string(body), 403)
	headers["X-CSRF-Token"] = csrf
	_, data := browserRequest(t, server, "POST", prefix+"/accounts/commands", cookie, headers, string(body), 200)
	var result store.AccountResult
	if json.Unmarshal(data, &result) != nil || result.Account.ID != command.ID {
		t.Fatal("invalid account result")
	}
	browserRequest(t, server, "POST", prefix+"/accounts/commands", cookie, headers, string(body), 200)
	browserRequest(t, server, "POST", prefix+"/accounts/commands", cookie, headers, `{"operation":"create","operation":"rotate"}`, 400)
	browserRequest(t, server, "POST", prefix+"/accounts/commands", cookie, headers, `{"plaintext_credential":"must-not-be-accepted"}`, 400)
	browserRequest(t, server, "GET", prefix+"/accounts?limit=101", cookie, nil, "", 400)
	browserRequest(t, server, "GET", prefix+"/accounts?limit=1", cookie, nil, "", 200)
	browserRequest(t, server, "GET", prefix+"/accounts/"+command.ID, cookie, nil, "", 200)
	browserRequest(t, server, "GET", "/v1/tenants/"+secure.NewID()+"/partners/"+scope.Partner+"/accounts", cookie, nil, "", 401)
}
