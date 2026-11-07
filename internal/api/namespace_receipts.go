package api

import (
	"net/http"

	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) namespaceReceipt(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var command store.PathCommand
	if err = boundedControlInput(w, r, 16<<10, &command); err != nil {
		fail(w, 400, "invalid_path_receipt_command")
		return
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || !store.ValidNamespaceRequestKey(key) {
		fail(w, 400, "invalid_path_receipt_key")
		return
	}
	receipt, err := s.Service.ReadPathCommandReceipt(r.Context(), identity, key, command)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, receipt)
}
