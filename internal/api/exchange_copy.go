package api

import (
	"net/http"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) copyExchange(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var request store.ExchangeCopyRequest
	if err = boundedControlInput(w, r, 16<<10, &request); err != nil {
		fail(w, 400, "invalid_exchange_copy")
		return
	}
	result, err := s.Service.CopyReceivedExchange(r.Context(), identity, r.Header.Get("Idempotency-Key"), request)
	if err != nil {
		failure(w, err)
		return
	}
	code := 201
	if result.Replayed {
		code = 200
	}
	respond(w, code, result)
}
