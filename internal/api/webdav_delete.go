package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func davDeleteInput(w http.ResponseWriter, r *http.Request) bool {
	tag, present, valid := tusHeader(r, "If-Match")
	if !present {
		fail(w, 428, "dav_delete_requires_exact_source_revision")
		return false
	}
	if _, _, ok := davFileTag(tag); !valid || !ok {
		fail(w, 400, "invalid_dav_delete_revision")
		return false
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_delete_requires_original_key")
		return false
	}
	if r.ContentLength != 0 {
		fail(w, 415, "dav_delete_body_unsupported")
		return false
	}
	for _, name := range []string{"If-None-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range", "Destination", "Overwrite"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_delete_condition")
			return false
		}
	}
	if depth, present, valid := tusHeader(r, "Depth"); present && (!valid || depth != "infinity") {
		fail(w, 400, "unsupported_dav_delete_depth")
		return false
	}
	return true
}

func (s *Server) davDelete(w http.ResponseWriter, r *http.Request, scope store.Scope, source string) {
	fileID, digest, valid := davFileTag(r.Header.Get("If-Match"))
	if !valid {
		fail(w, 400, "invalid_dav_delete_revision")
		return
	}
	result, err := s.Service.RemoveFileIfCurrent(r.Context(), scope, r.Header.Get("Idempotency-Key"), source, fileID, digest)
	switch {
	case errors.Is(err, store.ErrRevision), errors.Is(err, store.ErrNotFound):
		fail(w, 412, "dav_delete_condition_failed")
		return
	case errors.Is(err, custody.ErrNamespaceFileProfile):
		w.Header().Set("Allow", davDirectoryMethods)
		fail(w, 405, "dav_file_delete_profile_only")
		return
	case err != nil:
		failure(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if result.Replayed {
		respond(w, 200, map[string]any{"result": result, "namespace_state": "not-asserted-original-receipt"})
		return
	}
	w.Header().Set("X-Freightctl-Namespace-State", "removed-at-commit")
	w.Header().Set("X-Freightctl-Event-ID", result.Entry.EventID)
	w.WriteHeader(http.StatusNoContent)
}
