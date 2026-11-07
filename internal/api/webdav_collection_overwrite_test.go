package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVCollectionOverwriteRequiresExactSourceAndDestinationIdentities(t *testing.T) {
	const base = "https://localhost/v1/tenants/t/partners/p/dav/"
	for _, method := range []string{"MOVE", "COPY"} {
		request := func() *http.Request {
			r := httptest.NewRequest(method, base+"source/", nil)
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
			r.Header.Set("Idempotency-Key", "collection-overwrite-original")
			r.Header.Set("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:1")
			r.Header.Set("X-Freightctl-Destination-Revision", "20000000-1111-4111-8111-111111111111:2")
			r.Header.Set("Overwrite", "T")
			r.Header.Set("Destination", base+"target/")
			return r
		}
		t.Run(method, func(t *testing.T) {
			r := request()
			w := httptest.NewRecorder()
			if !prepareDAVRequest(w, r) {
				t.Fatalf("explicit overwrite with both namespace identities refused before service:%d", w.Code)
			}
			for _, test := range []struct {
				name   string
				change func(*http.Request)
				status int
			}{
				{"missing destination condition", func(r *http.Request) { r.Header.Del("X-Freightctl-Destination-Revision") }, 428},
				{"duplicate destination condition", func(r *http.Request) {
					r.Header.Add("X-Freightctl-Destination-Revision", "20000000-1111-4111-8111-111111111111:3")
				}, 400},
				{"noncanonical revision", func(r *http.Request) {
					r.Header.Set("X-Freightctl-Destination-Revision", "20000000-1111-4111-8111-111111111111:02")
				}, 400},
				{"missing destination identity", func(r *http.Request) { r.Header.Set("X-Freightctl-Destination-Revision", ":2") }, 400},
				{"condition with non-overwrite", func(r *http.Request) { r.Header.Set("Overwrite", "F") }, 400},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := request()
					test.change(r)
					w := httptest.NewRecorder()
					if prepareDAVRequest(w, r) || w.Code != test.status {
						t.Fatal("destination metadata condition was missing,ambiguous or ignored", w.Code)
					}
				})
			}
		})
	}
}

func TestDAVDestinationNamespaceConditionCannotBeIgnoredByOtherMethods(t *testing.T) {
	for _, method := range []string{"PUT", "MKCOL", "DELETE", "PROPPATCH", "MOVE", "COPY"} {
		path := "https://localhost/v1/tenants/t/partners/p/dav/file.dat"
		if method == "MKCOL" {
			path += "/"
		}
		r := httptest.NewRequest(method, path, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("X-Freightctl-Destination-Revision", "20000000-1111-4111-8111-111111111111:1")
		w := httptest.NewRecorder()
		if prepareDAVRequest(w, r) || w.Code != 400 {
			t.Fatal("known destination namespace condition ignored by unrelated method", method, w.Code)
		}
	}
}
