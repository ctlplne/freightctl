package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestNamespaceReceiptLookupRejectsAmbiguousOriginalCommandBeforeResources(t *testing.T) {
	for _, body := range []string{`null`, `{"operation":"remove_tree","path":"/one","path":"/two"}`, `{"operation":"remove_tree","path":"/one","approved":true}`, `{"operation":"remove_tree","path":"/one","expected_revision":1,"expected_revi\u017fion":2}`, strings.Repeat(" ", 16<<10) + `{}`} {
		r := httptest.NewRequest("POST", "https://localhost/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/namespace/receipts", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("Idempotency-Key", "original-command")
		w := httptest.NewRecorder()
		New(&custody.Service{}, nil).ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_path_receipt_command"`) {
			t.Fatal("receipt lookup lacks a strict read-only original-command boundary", w.Code)
		}
	}
}

func TestNamespaceReceiptLookupRequiresOneOriginalKeyBeforeResources(t *testing.T) {
	for _, keys := range [][]string{nil, {""}, {"space key"}, {"../path"}, {strings.Repeat("x", 129)}, {"original", "other"}} {
		r := httptest.NewRequest("POST", "https://localhost/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/namespace/receipts", strings.NewReader(`{"operation":"mkdir","path":"/safe"}`))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		for _, key := range keys {
			r.Header.Add("Idempotency-Key", key)
		}
		w := httptest.NewRecorder()
		New(&custody.Service{}, nil).ServeHTTP(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_path_receipt_key"`) {
			t.Fatal("receipt lookup reached storage without an exact original key", w.Code)
		}
	}
}
