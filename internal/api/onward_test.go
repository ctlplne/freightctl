package api

import (
	"github.com/ctlplne/freightctl/internal/custody"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnwardRoutesRefuseInventedAuthorityBeforeDatabase(t *testing.T) {
	handler := New(&custody.Service{MaxFile: 1024}, nil)
	for _, route := range []string{"onward/previews", "onward/runs", "onward/receipts"} {
		request := httptest.NewRequest("POST", "https://freightctl.invalid/v1/tenants/11111111-1111-4111-8111-111111111111/partners/22222222-2222-4222-8222-222222222222/"+route, strings.NewReader(`{"approved":true,"recipient":"unregistered"}`))
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 400 {
			t.Fatal("missing reviewed onward route or invented authority reached database", route, response.Code)
		}
	}
}
