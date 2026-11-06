package api

import (
	"net/http"

	"github.com/ctlplne/freightctl/internal/custody"
)

func (s *Server) ingressDescriptor(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var request custody.IngressDescriptorRequest
	if err = workflowInput(w, r, &request); err != nil {
		fail(w, 400, "invalid_ingress_descriptor")
		return
	}
	result, err := s.Service.PrepareArtifactIngress(r.Context(), identity, request)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
