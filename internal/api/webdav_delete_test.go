package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileDeleteRequiresExactRevisionBeforeCustody(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Idempotency-Key", "dav-file-remove")
	w := httptest.NewRecorder()
	if prepareDAVRequest(w, r) || w.Code != 428 {
		t.Fatalf("file deletion admitted no immutable source condition: status=%d", w.Code)
	}
}

func TestDAVFileDeleteRefusesAmbiguousConditionsBodiesAndForeignMutationHeaders(t *testing.T) {
	makeRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodDelete, "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("Idempotency-Key", "dav-remove")
		r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
		return r
	}
	for _, depth := range []string{"", "infinity"} {
		r := makeRequest()
		if depth != "" {
			r.Header.Set("Depth", depth)
		}
		if !prepareDAVRequest(httptest.NewRecorder(), r) {
			t.Fatal("exact empty file-removal contract refused")
		}
	}
	for name, mutate := range map[string]func(*http.Request){
		"weak":                 func(r *http.Request) { r.Header.Set("If-Match", "W/"+r.Header.Get("If-Match")) },
		"wildcard":             func(r *http.Request) { r.Header.Set("If-Match", "*") },
		"duplicate revision":   func(r *http.Request) { r.Header.Add("If-Match", r.Header.Get("If-Match")) },
		"missing key":          func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate key":        func(r *http.Request) { r.Header.Add("Idempotency-Key", "another-command") },
		"body":                 func(r *http.Request) { r.ContentLength = 1 },
		"streaming body":       func(r *http.Request) { r.ContentLength = -1 },
		"partial tree":         func(r *http.Request) { r.Header.Set("Depth", "0") },
		"duplicate depth":      func(r *http.Request) { r.Header.Add("Depth", "infinity"); r.Header.Add("Depth", "infinity") },
		"opposed condition":    func(r *http.Request) { r.Header.Set("If-None-Match", "*") },
		"lock condition":       func(r *http.Request) { r.Header.Set("If", "(<untrusted-token>)") },
		"other date condition": func(r *http.Request) { r.Header.Set("If-Unmodified-Since", "Wed, 21 Oct 2015 07:28:00 GMT") },
		"partial bytes":        func(r *http.Request) { r.Header.Set("Content-Range", "bytes 0-1/2") },
		"destination":          func(r *http.Request) { r.Header.Set("Destination", "https://outside.invalid/artifact") },
		"overwrite":            func(r *http.Request) { r.Header.Set("Overwrite", "T") },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			mutate(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code < 400 || w.Code >= 500 {
				t.Fatal("ambiguous file-removal request reached custody")
			}
		})
	}
}
