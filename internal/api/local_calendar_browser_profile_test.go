package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
)

const localCalendarBrowserSessionLifetime = 10 * time.Minute

func TestLocalCalendarBrowserProfileServesTheRealLoginDocument(t *testing.T) {
	// Use the native journey's exact constructor setting,without PostgreSQL or
	// Chrome. An invalid session configuration refuses every route before login.
	handler := NewWithBrowserLifetime(&custody.Service{}, nil, false, localCalendarBrowserSessionLifetime)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "https://localhost/", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("native calendar profile cannot reach login: status=%d", w.Code)
	}
	// Preserve the production maximum. The fixture must fit it,not enlarge it.
	bad := NewWithBrowserLifetime(&custody.Service{}, nil, false, 20*time.Minute)
	w = httptest.NewRecorder()
	bad.ServeHTTP(w, httptest.NewRequest("GET", "https://localhost/", nil))
	if w.Code != 503 {
		t.Fatal("unsupported production session lifetime was accepted")
	}
}
