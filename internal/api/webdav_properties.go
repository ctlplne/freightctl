package api

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

type davPropertyContext struct{}
type davPropertyInput struct {
	Entry    string
	Revision int64
	Changes  []namespaceprops.Change
}

// Namespace conditions protect metadata revisions; a file's byte ETag alone
// cannot detect another metadata edit or a removed/recreated directory.
func davPropertyMutationInput(w http.ResponseWriter, r *http.Request) bool {
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/xml" && media != "text/xml" || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") {
		fail(w, 415, "dav_utf8_xml_required")
		return false
	}
	changes, err := namespaceprops.ParseUpdate(http.MaxBytesReader(w, r.Body, namespaceprops.MaxRequestBytes))
	if err != nil {
		fail(w, 400, "invalid_dav_property_update")
		return false
	}
	if err = namespaceprops.ValidateChanges(changes); errors.Is(err, namespaceprops.ErrProtected) {
		fail(w, 403, "dav_protected_property")
		return false
	} else if err != nil {
		fail(w, 400, "invalid_dav_property_update")
		return false
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_properties_require_original_key")
		return false
	}
	condition, present, valid := tusHeader(r, "X-Freightctl-Namespace-Revision")
	if !present {
		fail(w, 428, "dav_properties_require_namespace_revision")
		return false
	}
	parts := strings.Split(condition, ":")
	if !valid || len(parts) != 2 || !store.ValidID(parts[0]) {
		fail(w, 400, "invalid_dav_namespace_revision")
		return false
	}
	revision, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != parts[1] {
		fail(w, 400, "invalid_dav_namespace_revision")
		return false
	}
	for _, name := range []string{"If-Match", "If-None-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range", "Destination", "Overwrite", "Depth"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_property_condition")
			return false
		}
	}
	*r = *r.WithContext(context.WithValue(r.Context(), davPropertyContext{}, davPropertyInput{Entry: parts[0], Revision: revision, Changes: changes}))
	return true
}

func (s *Server) davPropertyMutation(w http.ResponseWriter, r *http.Request, scope store.Scope, virtual, base string) {
	input, valid := r.Context().Value(davPropertyContext{}).(davPropertyInput)
	if !valid {
		fail(w, 400, "invalid_dav_property_update")
		return
	}
	command := store.PathCommand{Operation: "properties", Path: virtual, ExpectedEntryID: input.Entry, ExpectedRevision: &input.Revision, PropertyChanges: input.Changes}
	result, err := s.Service.PathCommand(r.Context(), scope, r.Header.Get("Idempotency-Key"), command)
	if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrNotFound) {
		fail(w, 412, "dav_property_condition_failed")
		return
	}
	if errors.Is(err, store.ErrLimit) {
		fail(w, 507, "dav_property_capacity_required")
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
	body, err := webdav.PropertyUpdateResponse(base, webdav.Resource{Path: result.Entry.Path, Directory: result.Entry.Kind == "dir"}, input.Changes)
	if err != nil {
		fail(w, 503, "dav_properties_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("X-Freightctl-Namespace-State", "properties-changed-at-commit")
	w.Header().Set("X-Freightctl-Event-ID", result.Entry.EventID)
	w.Header().Set("X-Freightctl-Namespace-Revision", result.Entry.ID+":"+strconv.FormatInt(result.Entry.Revision, 10))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(207)
	_, _ = w.Write(body)
}
