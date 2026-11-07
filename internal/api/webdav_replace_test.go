package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVReplacementRequiresOneExactStrongRevisionBeforeReadingBytes(t *testing.T) {
	request := func() *http.Request {
		r := httptest.NewRequest("PUT", "https://localhost/v1/tenants/t/partners/p/dav/current.dat", strings.NewReader("replacement bytes"))
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
		r.Header.Set("Idempotency-Key", "dav-exact-replacement")
		r.Header.Set("X-Content-SHA256", strings.Repeat("c", 64))
		return r
	}
	w := httptest.NewRecorder()
	if !prepareDAVRequest(w, request()) {
		t.Fatal("exact conditional replacement refused before ordinary custody", w.Code)
	}
	for name, change := range map[string]func(*http.Request){
		"wildcard":       func(r *http.Request) { r.Header.Set("If-Match", "*") },
		"weak":           func(r *http.Request) { r.Header.Set("If-Match", "W/"+r.Header.Get("If-Match")) },
		"duplicate":      func(r *http.Request) { r.Header.Add("If-Match", r.Header.Get("If-Match")) },
		"two conditions": func(r *http.Request) { r.Header.Set("If-None-Match", "*") },
		"malformed":      func(r *http.Request) { r.Header.Set("If-Match", `"other"`) },
		"date":           func(r *http.Request) { r.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT") },
		"DAV If":         func(r *http.Request) { r.Header.Set("If", "(<lock-token>)") },
		"partial":        func(r *http.Request) { r.Header.Set("Content-Range", "bytes 0-2/3") },
		"unknown length": func(r *http.Request) { r.ContentLength = -1 },
		"missing key":    func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"invalid digest": func(r *http.Request) { r.Header.Set("X-Content-SHA256", strings.Repeat("x", 64)) },
	} {
		t.Run(name, func(t *testing.T) {
			r := request()
			change(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code < 400 {
				t.Fatal("ambiguous replacement admitted")
			}
		})
	}
}
