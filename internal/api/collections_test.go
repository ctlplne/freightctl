package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestCollectionAPIRejectsInventedProofAndAuthorityBeforeStorage(t *testing.T) {
	h := New(&custody.Service{}, nil)
	for _, route := range []string{"workflow-collections/preview", "workflow-collections", "workflow-collections/00000000-0000-0000-0000-000000000003/work"} {
		for _, body := range []string{`{"approved":true}`, `{"producer_complete":true}`, `{"expected_revision":1,"expected_revision":2}`, strings.Repeat(" ", 33<<10)} {
			r := httptest.NewRequest(http.MethodPost, "https://freightctl.invalid/v1/tenants/00000000-0000-0000-0000-000000000001/partners/00000000-0000-0000-0000-000000000002/"+route, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 400 {
				t.Fatalf("collection must refuse invented completion/authority: %s: %d", route, w.Code)
			}
		}
	}
}
