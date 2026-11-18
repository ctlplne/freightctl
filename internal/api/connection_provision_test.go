package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

const testProvisionRoute = "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/connections/provisioning/commands"

func TestConnectionProvisionRejectsInvalidHTTPCommandsBeforeStorage(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	valid := `{"operation":"provision","recipient_actor_id":"00000000-0000-0000-0000-000000000003","recipient_authority_revision":1,"source":{"id":"00000000-0000-0000-0000-000000000004","version":1,"hash":"` + strings.Repeat("a", 64) + `"}}`
	for _, example := range []struct {
		name, body, key string
		auth            bool
		status          int
	}{
		{"authentication", valid, "provision-key", false, 401},
		{"idempotency", valid, "", true, 400},
		{"duplicate", `{"operation":"provision",` + valid[1:], "provision-key", true, 400},
		{"authority alias", strings.Replace(valid, "recipient_authority_revision", "Recipient_Authority_Revision", 1), "provision-key", true, 400},
		{"credential selector", `{"password_reference":"fixture",` + valid[1:], "provision-key", true, 400},
		{"body bound", valid + strings.Repeat(" ", 4096), "provision-key", true, 400},
	} {
		t.Run(example.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, testProvisionRoute, strings.NewReader(example.body))
			if example.auth {
				r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			}
			r.Header.Set("Idempotency-Key", example.key)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != example.status {
				t.Fatalf("invalid operator request status %d, expected %d", w.Code, example.status)
			}
		})
	}
}

func TestConnectionProvisionUsesOrdinaryBrowserMutationGuards(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, example := range []struct{ origin, reason string }{
		{"https://unrelated.invalid", "browser_origin_denied"},
		{"https://freightctl.invalid", "csrf_required"},
	} {
		r := httptest.NewRequest(http.MethodPost, testProvisionRoute, strings.NewReader(`{"operation":"provision"}`))
		r.Header.Set("Origin", example.origin)
		r.AddCookie(&http.Cookie{Name: browserCookieName, Value: "00000000-0000-0000-0000-000000000001.00000000-0000-0000-0000-000000000002." + strings.Repeat("0", 64)})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var body map[string]string
		if w.Code != 403 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body["error"] != example.reason {
			t.Fatalf("browser mutation expected %s, got status %d", example.reason, w.Code)
		}
	}
}

func TestConnectionProvisionChoicesRefuseUnboundedPagesBeforeStorage(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	prefix := strings.TrimSuffix(testProvisionRoute, "commands")
	for _, choice := range []string{"sources", "recipients", "assignments"} {
		for _, query := range []string{"?limit=not-a-number", "?limit=0", "?limit=101", "?after=not-an-id"} {
			r := httptest.NewRequest(http.MethodGet, prefix+choice+query, nil)
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("invalid %s page status %d", choice, w.Code)
			}
		}
	}
}
