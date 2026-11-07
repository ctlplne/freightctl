package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileCopyRequiresExactSourceRevisionBeforeCustody(t *testing.T) {
	r := httptest.NewRequest("COPY", "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Idempotency-Key", "dav-file-copy")
	r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/copied.dat")
	r.Header.Set("Overwrite", "F")
	w := httptest.NewRecorder()
	if prepareDAVRequest(w, r) || w.Code != 428 {
		t.Fatalf("file copy admitted no immutable source condition: status=%d", w.Code)
	}
}

func TestDAVFileCopyConfinesDestinationAndRefusesOverwriteOrAmbiguousConditions(t *testing.T) {
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("COPY", "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
		r.Header.Set("Destination", "https://localhost/v1/tenants/t/partners/p/dav/copy.dat")
		r.Header.Set("Overwrite", "F")
		r.Header.Set("Idempotency-Key", "dav-copy")
		return r
	}
	if !prepareDAVRequest(httptest.NewRecorder(), makeRequest()) {
		t.Fatal("exact same-scope no-overwrite copy refused")
	}
	for name, mutate := range map[string]func(*http.Request){
		"foreign destination": func(r *http.Request) { r.Header.Set("Destination", "https://outside.invalid/artifact") },
		"other scope":         func(r *http.Request) { r.Header.Set("Destination", "/v1/tenants/other/partners/p/dav/copy.dat") },
		"selector":            func(r *http.Request) { r.Header.Set("Destination", r.Header.Get("Destination")+"?path=/another") },
		"separator":           func(r *http.Request) { r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/a%2fb") },
		"overwrite":           func(r *http.Request) { r.Header.Set("Overwrite", "T") },
		"body":                func(r *http.Request) { r.ContentLength = 1 },
		"weak revision":       func(r *http.Request) { r.Header.Set("If-Match", "W/"+r.Header.Get("If-Match")) },
		"duplicate revision":  func(r *http.Request) { r.Header.Add("If-Match", r.Header.Get("If-Match")) },
		"missing key":         func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"opposed condition":   func(r *http.Request) { r.Header.Set("If-None-Match", "*") },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			mutate(r)
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code < 400 || w.Code >= 500 {
				t.Fatal("unsafe copy reached custody")
			}
		})
	}
}
