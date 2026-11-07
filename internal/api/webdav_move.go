package api

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

func davFileTag(value string) (string, string, bool) {
	const prefix = `"freightctl-`
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, `"`) {
		return "", "", false
	}
	body := strings.TrimSuffix(strings.TrimPrefix(value, prefix), `"`)
	if len(body) != 101 || body[36] != '-' || !store.ValidID(body[:36]) || strings.Trim(body[37:], "0123456789abcdef") != "" {
		return "", "", false
	}
	return body[:36], body[37:], true
}

func davMoveInput(w http.ResponseWriter, r *http.Request) bool {
	return davFileMappingInput(w, r, "move")
}

func davFileMappingInput(w http.ResponseWriter, r *http.Request, operation string) bool {
	tag, present, valid := tusHeader(r, "If-Match")
	if !present {
		fail(w, 428, "dav_"+operation+"_requires_exact_source_revision")
		return false
	}
	if _, _, ok := davFileTag(tag); !valid || !ok {
		fail(w, 400, "invalid_dav_"+operation+"_revision")
		return false
	}
	overwrite, _, valid := tusHeader(r, "Overwrite")
	if !valid || overwrite != "F" {
		fail(w, 428, "dav_"+operation+"_requires_no_overwrite")
		return false
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_"+operation+"_requires_original_key")
		return false
	}
	if r.ContentLength != 0 {
		fail(w, 415, "dav_"+operation+"_body_unsupported")
		return false
	}
	for _, name := range []string{"If-None-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_"+operation+"_condition")
			return false
		}
	}
	if depth, present, valid := tusHeader(r, "Depth"); present && (!valid || depth != "0" && depth != "1" && depth != "infinity") {
		fail(w, 400, "invalid_dav_"+operation+"_depth")
		return false
	}
	base := "/v1/tenants/" + url.PathEscape(strings.Split(r.URL.Path, "/")[3]) + "/partners/" + url.PathEscape(strings.Split(r.URL.Path, "/")[5]) + "/dav/"
	if _, err := davMoveDestination(r, base); err != nil {
		fail(w, 400, "invalid_dav_"+operation+"_destination")
		return false
	}
	return true
}

func davMoveDestination(r *http.Request, base string) (string, error) {
	value, present, valid := tusHeader(r, "Destination")
	if !present || !valid || len(value) > 8192 {
		return "", webdav.ErrRequest
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", webdav.ErrRequest
	}
	if strings.HasSuffix(u.Path, "/") {
		return "", webdav.ErrRequest
	}
	if u.IsAbs() {
		if u.Scheme != "https" || !strings.EqualFold(u.Host, r.Host) {
			return "", webdav.ErrRequest
		}
	} else if u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "", webdav.ErrRequest
	}
	return webdav.VirtualPath(u.EscapedPath(), base)
}

func (s *Server) davMove(w http.ResponseWriter, r *http.Request, scope store.Scope, source, base string) {
	target, err := davMoveDestination(r, base)
	if err != nil {
		fail(w, 400, "invalid_dav_move_destination")
		return
	}
	fileID, digest, valid := davFileTag(r.Header.Get("If-Match"))
	if !valid {
		fail(w, 400, "invalid_dav_move_revision")
		return
	}
	result, err := s.Service.MoveFileIfCurrent(r.Context(), scope, r.Header.Get("Idempotency-Key"), source, target, fileID, digest)
	switch {
	case errors.Is(err, store.ErrExists), errors.Is(err, store.ErrRevision), errors.Is(err, store.ErrNotFound):
		fail(w, 412, "dav_move_condition_failed")
		return
	case errors.Is(err, custody.ErrNamespaceParent):
		fail(w, 409, "dav_parent_collection_required")
		return
	case errors.Is(err, custody.ErrNamespaceFileProfile):
		w.Header().Set("Allow", davDirectoryMethods)
		fail(w, 405, "dav_file_move_profile_only")
		return
	case err != nil:
		failure(w, err)
		return
	}
	status, state := 201, "moved-at-commit"
	if result.Replayed {
		status, state = 200, "not-asserted-original-receipt"
	} else {
		w.Header().Set("Location", webdav.Href(base, webdav.Resource{Path: result.Entry.Path}))
	}
	respond(w, status, map[string]any{"result": result, "namespace_state": state})
}
