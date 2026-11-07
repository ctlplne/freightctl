package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCollectionCreateRequiresAnOriginalCommandKey(t *testing.T) {
	r := httptest.NewRequest("MKCOL", "https://localhost/v1/tenants/t/partners/p/dav/folder", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	w := httptest.NewRecorder()
	if prepareDAVRequest(w, r) || w.Code != 400 {
		t.Fatalf("DAV directory creation admitted no durable command key: status=%d", w.Code)
	}
}

func TestDAVCollectionCreateRefusesBodiesAndAmbiguousConditions(t *testing.T) {
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("MKCOL", "https://localhost/v1/tenants/t/partners/p/dav/folder", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("Idempotency-Key", "dav-folder-command")
		return r
	}
	for _, conditional := range []bool{false, true} {
		r := makeRequest()
		if conditional {
			r.Header.Set("If-None-Match", "*")
		}
		if !prepareDAVRequest(httptest.NewRecorder(), r) {
			t.Fatal("empty keyed create request refused")
		}
	}
	for name, change := range map[string]func(*http.Request){
		"body":                       func(r *http.Request) { r.ContentLength = 1 },
		"streamed body":              func(r *http.Request) { r.ContentLength = -1 },
		"duplicate key":              func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") },
		"duplicate absent condition": func(r *http.Request) { r.Header["If-None-Match"] = []string{"*", "*"} },
		"other condition":            func(r *http.Request) { r.Header.Set("If-None-Match", `"another"`) },
		"tag match":                  func(r *http.Request) { r.Header.Set("If-Match", "") },
		"time match":                 func(r *http.Request) { r.Header.Set("If-Unmodified-Since", "Fri, 06 Nov 2026 12:00:00 GMT") },
		"DAV condition":              func(r *http.Request) { r.Header.Set("If", "(<lock-token>)") },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			change(r)
			if prepareDAVRequest(httptest.NewRecorder(), r) {
				t.Fatal("unsupported collection request admitted")
			}
		})
	}
}
