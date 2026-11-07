package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileCopyAdmitsOnlyAnExplicitBoundedOverwriteDecision(t *testing.T) {
	r := httptest.NewRequest("COPY", "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
	r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
	r.Header.Set("Idempotency-Key", "dav-copy-overwrite")
	r.Header.Set("Overwrite", "T")
	r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/target.dat")
	w := httptest.NewRecorder()
	if !prepareDAVRequest(w, r) {
		t.Fatal("exact explicit file copy overwrite refused before authority check", w.Code)
	}
}
