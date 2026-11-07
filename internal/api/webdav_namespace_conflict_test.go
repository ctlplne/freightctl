package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileAndCollectionCreationCannotIgnoreANamespaceCondition(t *testing.T) {
	const base = "https://localhost/v1/tenants/t/partners/p/dav/"
	for _, method := range []string{"PUT", "MKCOL", "MOVE", "COPY", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			target := base + "file.dat"
			if method == "MKCOL" {
				target = base + "folder/"
			}
			r := httptest.NewRequest(method, target, nil)
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
			r.Header.Set("Idempotency-Key", "namespace-condition-original")
			r.Header.Set("X-Freightctl-Namespace-Revision", "10000000-1111-4111-8111-111111111111:2")
			if method == "PUT" || method == "MKCOL" {
				r.Header.Set("If-None-Match", "*")
			} else {
				r.Header.Set("If-Match", `"freightctl-20000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
			}
			if method == "PUT" {
				r.Header.Set("X-Content-SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
			}
			if method == "MOVE" || method == "COPY" {
				r.Header.Set("Overwrite", "F")
				r.Header.Set("Destination", base+"target.dat")
			}
			w := httptest.NewRecorder()
			if prepareDAVRequest(w, r) || w.Code != 400 {
				t.Fatal("namespace condition was silently ignored before mutation;status", w.Code)
			}
		})
	}
}
