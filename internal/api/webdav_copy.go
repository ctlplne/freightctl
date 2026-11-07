package api

import (
	"errors"
	"net/http"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

func (s *Server) davCopy(w http.ResponseWriter, r *http.Request, scope store.Scope, source, base string) {
	target, err := davMoveDestination(r, base)
	if err != nil {
		fail(w, 400, "invalid_dav_copy_destination")
		return
	}
	fileID, digest, valid := davFileTag(r.Header.Get("If-Match"))
	if !valid {
		fail(w, 400, "invalid_dav_copy_revision")
		return
	}
	result, err := s.Service.CopyFileIfCurrent(r.Context(), scope, r.Header.Get("Idempotency-Key"), source, target, fileID, digest)
	switch {
	case errors.Is(err, store.ErrExists), errors.Is(err, store.ErrRevision), errors.Is(err, store.ErrNotFound):
		fail(w, 412, "dav_copy_condition_failed")
		return
	case errors.Is(err, custody.ErrNamespaceParent):
		fail(w, 409, "dav_parent_collection_required")
		return
	case errors.Is(err, custody.ErrNamespaceFileProfile):
		w.Header().Set("Allow", davDirectoryMethods)
		fail(w, 405, "dav_file_copy_profile_only")
		return
	case err != nil:
		failure(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	status, state := 201, "copied-at-commit"
	if result.Replayed {
		status, state = 200, "not-asserted-original-receipt"
	} else {
		w.Header().Set("Location", webdav.Href(base, webdav.Resource{Path: result.Entry.Path}))
	}
	respond(w, status, map[string]any{"result": result, "namespace_state": state})
}
