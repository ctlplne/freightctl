package api

import (
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) partners(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var result any
	if r.Method == http.MethodPost {
		var request store.PartnerCommand
		if workflowInput(w, r, &request) != nil {
			err = store.ErrPartnerInput
		} else {
			result, err = s.Service.DB.RegisterPartner(r.Context(), scope, r.Header.Get("Idempotency-Key"), request)
		}
	} else {
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err != nil {
			err = store.ErrPartnerInput
		} else {
			result, err = s.Service.DB.Partners(r.Context(), scope, r.URL.Query().Get("after"), limit)
		}
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
