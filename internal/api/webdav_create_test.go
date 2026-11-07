package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCreateRequiresAnExplicitAbsentResourceConditionBeforeReadingBytes(t *testing.T) {
	r := httptest.NewRequest("PUT", "https://localhost/v1/tenants/t/partners/p/dav/new.dat", strings.NewReader("inert artifact"))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	w := httptest.NewRecorder()
	accepted := prepareDAVRequest(w, r)
	if accepted || w.Code != 428 {
		t.Fatalf("DAV create did not require an explicit non-overwrite condition: admitted=%t status=%d", accepted, w.Code)
	}
}

func TestDAVCreateInputKeepsExactConditionsDigestLengthAndOriginalKey(t *testing.T) {
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("PUT", "https://localhost/v1/tenants/t/partners/p/dav/new.dat", strings.NewReader("inert artifact"))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-None-Match", "*")
		r.Header.Set("Idempotency-Key", "dav-create-command")
		r.Header.Set("X-Content-SHA256", strings.Repeat("b", 64))
		return r
	}
	r := makeRequest()
	w := httptest.NewRecorder()
	if !prepareDAVRequest(w, r) {
		t.Fatal("explicit create-only contract refused before ordinary custody")
	}
	for name, change := range map[string]func(*http.Request){
		"other condition":     func(r *http.Request) { r.Header.Set("If-None-Match", `"other"`) },
		"duplicate condition": func(r *http.Request) { r.Header.Add("If-None-Match", "*") },
		"other match":         func(r *http.Request) { r.Header.Set("If-Match", "") },
		"DAV condition":       func(r *http.Request) { r.Header.Set("If", "(<lock-token>)") },
		"partial PUT":         func(r *http.Request) { r.Header.Set("Content-Range", "bytes 0-2/3") },
		"unknown length":      func(r *http.Request) { r.ContentLength = -1 },
		"missing key":         func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate key":       func(r *http.Request) { r.Header.Add("Idempotency-Key", "another") },
		"invalid digest":      func(r *http.Request) { r.Header.Set("X-Content-SHA256", strings.Repeat("x", 64)) },
		"duplicate digest":    func(r *http.Request) { r.Header.Add("X-Content-SHA256", strings.Repeat("b", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			change(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code < 400 {
				t.Fatal("ambiguous create contract admitted")
			}
		})
	}
}
