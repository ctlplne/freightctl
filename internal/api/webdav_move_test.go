package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileMoveRequiresTheExactSourceRevisionBeforeCustody(t *testing.T) {
	r := httptest.NewRequest("MOVE", "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/next.dat")
	r.Header.Set("Overwrite", "F")
	r.Header.Set("Idempotency-Key", "dav-file-move")
	w := httptest.NewRecorder()
	if prepareDAVRequest(w, r) || w.Code != 428 {
		t.Fatalf("file move admitted no exact immutable source condition: status=%d", w.Code)
	}
}

func TestDAVFileMovePinsStrongRevisionAndConfinesDestinationURIs(t *testing.T) {
	const id = "10000000-1111-4111-8111-111111111111"
	digest := strings.Repeat("b", 64)
	tag := `"freightctl-` + id + `-` + digest + `"`
	fileID, hash, ok := davFileTag(tag)
	if !ok || fileID != id || hash != digest {
		t.Fatal("ordinary immutable file validator refused")
	}
	for _, value := range []string{"*", "W/" + tag, tag + ", " + tag, strings.Trim(tag, `"`), strings.Replace(tag, digest, strings.Repeat("x", 64), 1)} {
		if _, _, ok := davFileTag(value); ok {
			t.Fatal("ambiguous or weak source revision admitted")
		}
	}
	makeRequest := func() *http.Request {
		r := httptest.NewRequest("MOVE", "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-Match", tag)
		r.Header.Set("Idempotency-Key", "dav-move")
		r.Header.Set("Overwrite", "F")
		r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/new%20file.dat")
		return r
	}
	for _, destination := range []string{"/v1/tenants/t/partners/p/dav/new%20file.dat", "https://localhost/v1/tenants/t/partners/p/dav/new%20file.dat"} {
		r := makeRequest()
		r.Header.Set("Destination", destination)
		if !prepareDAVRequest(httptest.NewRecorder(), r) {
			t.Fatal("same-scope canonical destination refused")
		}
		value, err := davMoveDestination(r, "/v1/tenants/t/partners/p/dav/")
		if err != nil || value != "/new file.dat" {
			t.Fatal("destination URI became another virtual name")
		}
	}
	for _, destination := range []string{"https://outside.invalid/v1/tenants/t/partners/p/dav/file.dat", "http://localhost/v1/tenants/t/partners/p/dav/file.dat", "https://user@localhost/v1/tenants/t/partners/p/dav/file.dat", "//outside.invalid/path", "/v1/tenants/other/partners/p/dav/file.dat", "/v1/tenants/t/partners/other/dav/file.dat", "/v1/tenants/t/partners/p/dav/a/../file.dat", "/v1/tenants/t/partners/p/dav/a%2fb", "/v1/tenants/t/partners/p/dav/file.dat?path=/another", "/v1/tenants/t/partners/p/dav/file.dat#another", "/v1/tenants/t/partners/p/dav/.freightctl/receipt", "/v1/tenants/t/partners/p/dav/folder/"} {
		r := makeRequest()
		r.Header.Set("Destination", destination)
		if prepareDAVRequest(httptest.NewRecorder(), r) {
			t.Fatalf("destination escaped exact namespace confinement: %q", destination)
		}
	}
	for name, change := range map[string]func(*http.Request){
		"body":                  func(r *http.Request) { r.ContentLength = 1 },
		"invalid overwrite":     func(r *http.Request) { r.Header.Set("Overwrite", "X") },
		"missing overwrite":     func(r *http.Request) { r.Header.Del("Overwrite") },
		"duplicate overwrite":   func(r *http.Request) { r.Header.Add("Overwrite", "T") },
		"missing key":           func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate destination": func(r *http.Request) { r.Header.Add("Destination", "/another") },
		"duplicate match":       func(r *http.Request) { r.Header.Add("If-Match", tag) },
		"extra condition":       func(r *http.Request) { r.Header.Set("If-None-Match", "*") },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRequest()
			change(r)
			if prepareDAVRequest(httptest.NewRecorder(), r) {
				t.Fatal("ambiguous move contract admitted")
			}
		})
	}
}
