package api

import (
	"net/http"
	"net/url"
)

func (s *Server) namespaceProperties(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	// A canonical path is at most1024 UTF8 bytes (at most3072 URL bytes).
	if len(r.URL.RawQuery) > 4<<10 {
		fail(w, 400, "invalid_namespace_property_query")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["path"]) != 1 || query.Get("path") == "" {
		fail(w, 400, "invalid_namespace_property_query")
		return
	}
	result, err := s.Service.ReadNamespacePropertySnapshot(r.Context(), identity, query.Get("path"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
