package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
)

func davCollectionDeleteInput(w http.ResponseWriter, r *http.Request) bool {
	condition, present, valid := tusHeader(r, "X-Freightctl-Namespace-Revision")
	if !present {
		fail(w, 428, "dav_collection_delete_requires_namespace_revision")
		return false
	}
	if _, _, exact := davNamespaceCondition(condition); !valid || !exact {
		fail(w, 400, "invalid_dav_namespace_revision")
		return false
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_collection_delete_requires_original_key")
		return false
	}
	if r.ContentLength != 0 {
		fail(w, 415, "dav_collection_delete_body_unsupported")
		return false
	}
	for _, name := range []string{"If-Match", "If-None-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range", "Destination", "Overwrite"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_collection_delete_condition")
			return false
		}
	}
	if depth, present, valid := tusHeader(r, "Depth"); present && (!valid || depth != "infinity") {
		fail(w, 400, "invalid_dav_collection_delete_depth")
		return false
	}
	// VirtualPath has already rejected malformed aliases. Never remove the
	// participant's mount root,including the /dav spelling without a slash.
	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	if len(parts) == 7 {
		fail(w, 400, "invalid_dav_collection_delete_source")
		return false
	}
	return true
}

func (s *Server) davCollectionDelete(w http.ResponseWriter, r *http.Request, scope store.Scope, source string) {
	entry, revision, valid := davNamespaceCondition(r.Header.Get("X-Freightctl-Namespace-Revision"))
	if !valid {
		fail(w, 400, "invalid_dav_namespace_revision")
		return
	}
	result, err := s.Service.PathCommand(r.Context(), scope, r.Header.Get("Idempotency-Key"), store.PathCommand{Operation: "remove_tree", Path: source, ExpectedEntryID: entry, ExpectedRevision: &revision})
	if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrNotFound) {
		fail(w, 412, "dav_collection_delete_condition_failed")
		return
	}
	if errors.Is(err, store.ErrLimit) {
		fail(w, 507, "dav_collection_delete_requires_smaller_tree")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	if result.Replayed {
		respond(w, 200, map[string]any{"result": result, "namespace_state": "not-asserted-original-receipt"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Freightctl-Namespace-State", "collection-removed-at-commit")
	w.Header().Set("X-Freightctl-Event-ID", result.Entry.EventID)
	w.Header().Set("X-Freightctl-Removed-Entries", strconv.Itoa(result.Changed))
	w.WriteHeader(http.StatusNoContent)
}
