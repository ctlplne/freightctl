package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDAVFileMoveAcceptsAnExplicitOverwriteDecisionWithoutRelaxingCopy(t *testing.T) {
	for _, method := range []string{"MOVE", "COPY"} {
		r := httptest.NewRequest(method, "https://localhost/v1/tenants/t/partners/p/dav/source.dat", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		r.Header.Set("If-Match", `"freightctl-10000000-1111-4111-8111-111111111111-`+strings.Repeat("b", 64)+`"`)
		r.Header.Set("Overwrite", "T")
		r.Header.Set("Destination", "/v1/tenants/t/partners/p/dav/target.dat")
		r.Header.Set("Idempotency-Key", "dav-explicit-overwrite")
		w := httptest.NewRecorder()
		accepted := prepareDAVRequest(w, r)
		if accepted != (method == "MOVE") {
			t.Fatalf("explicit file move/copy profile differs;method=%s;accepted=%t;status=%d", method, accepted, w.Code)
		}
	}
}
