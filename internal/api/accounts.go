package api

import (
	"github.com/ctlplne/freightctl/internal/store"
	"net/http"
	"strconv"
)

func (s *Server) accounts(w http.ResponseWriter, r *http.Request) {
	scope, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var result any
	switch r.Pattern {
	case "POST /v1/tenants/{tenant}/partners/{partner}/accounts/commands":
		var command store.AccountCommand
		if workflowInput(w, r, &command) != nil {
			err = store.ErrAccountInput
		} else {
			result, err = s.Service.DB.ChangeAccount(r.Context(), scope, r.Header.Get("Idempotency-Key"), command)
		}
	case "GET /v1/tenants/{tenant}/partners/{partner}/accounts/{account}":
		result, err = s.Service.DB.Account(r.Context(), scope, r.PathValue("account"))
	default:
		limit := 50
		if value := r.URL.Query().Get("limit"); value != "" {
			limit, err = strconv.Atoi(value)
		}
		if err != nil {
			err = store.ErrAccountInput
		} else {
			result, err = s.Service.DB.Accounts(r.Context(), scope, r.URL.Query().Get("after"), limit)
		}
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
