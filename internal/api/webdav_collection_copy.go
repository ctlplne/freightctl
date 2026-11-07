package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

func (s *Server) davCollectionCopy(w http.ResponseWriter, r *http.Request, scope store.Scope, source, base string) {
	target, err := davCollectionDestination(r, base)
	if err != nil {
		fail(w, 400, "invalid_dav_collection_copy_destination")
		return
	}
	entry, revision, valid := davNamespaceCondition(r.Header.Get("X-Freightctl-Namespace-Revision"))
	if !valid {
		fail(w, 400, "invalid_dav_namespace_revision")
		return
	}
	operation, depth := "copy_tree", "infinity"
	if r.Header.Get("Depth") == "0" {
		operation, depth = "copy_dir", "0"
	}
	result, err := s.Service.PathCommand(r.Context(), scope, r.Header.Get("Idempotency-Key"), store.PathCommand{Operation: operation, Path: source, Target: target, ExpectedEntryID: entry, ExpectedRevision: &revision})
	if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) {
		fail(w, 412, "dav_collection_copy_condition_failed")
		return
	}
	if errors.Is(err, store.ErrLimit) {
		fail(w, 507, "dav_collection_copy_requires_capacity")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	if result.Replayed {
		respond(w, 200, map[string]any{"result": result, "namespace_state": "not-asserted-original-receipt", "depth": depth})
		return
	}
	w.Header().Set("Location", webdav.Href(base, webdav.Resource{Path: result.Entry.Path, Directory: true}))
	respond(w, 201, map[string]any{"result": result, "namespace_state": "collection-copied-at-commit", "depth": depth})
}
