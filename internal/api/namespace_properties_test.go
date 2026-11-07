package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
)

func TestExplicitPropertyReadRejectsAmbiguousSelectorsBeforeService(t *testing.T) {
	handler := New(&custody.Service{}, nil)
	for _, query := range []string{"", "path=", "path=/one&path=/two", "path=/one&execute=true", "path=/one/../two", "path=/.freightctl/receipt", "path=%zz", "path=/e%CC%81.txt", "path=/" + strings.Repeat("x", 4096)} {
		r := httptest.NewRequest("GET", "https://localhost/v1/tenants/00000001-1111-4111-8111-111111111111/partners/00000002-1111-4111-8111-111111111111/namespace/properties?"+query, nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("ambiguous property query reached service or unimplemented route;status=%d", w.Code)
		}
	}
}
