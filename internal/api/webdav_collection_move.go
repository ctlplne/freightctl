package api

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

func davCollectionMoveInput(w http.ResponseWriter, r *http.Request) bool {
	return davCollectionMappingInput(w, r, "move")
}

func davCollectionCopyInput(w http.ResponseWriter, r *http.Request) bool {
	return davCollectionMappingInput(w, r, "copy")
}

func davCollectionMappingInput(w http.ResponseWriter, r *http.Request, operation string) bool {
	condition, present, valid := tusHeader(r, "X-Freightctl-Namespace-Revision")
	if !present {
		fail(w, 428, "dav_collection_"+operation+"_requires_namespace_revision")
		return false
	}
	if _, _, exact := davNamespaceCondition(condition); !valid || !exact {
		fail(w, 400, "invalid_dav_namespace_revision")
		return false
	}
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_collection_"+operation+"_requires_original_key")
		return false
	}
	overwrite, _, valid := tusHeader(r, "Overwrite")
	if !valid || overwrite != "F" && overwrite != "T" {
		fail(w, 428, "dav_collection_"+operation+"_requires_explicit_overwrite")
		return false
	}
	targetCondition, targetPresent, targetValid := tusHeader(r, "X-Freightctl-Destination-Revision")
	if overwrite == "T" {
		if !targetPresent {
			fail(w, 428, "dav_collection_"+operation+"_requires_destination_revision")
			return false
		}
		if _, _, exact := davNamespaceCondition(targetCondition); !targetValid || !exact {
			fail(w, 400, "invalid_dav_destination_namespace_revision")
			return false
		}
	} else if targetPresent {
		fail(w, 400, "unexpected_dav_destination_namespace_revision")
		return false
	}
	if r.ContentLength != 0 {
		fail(w, 415, "dav_collection_"+operation+"_body_unsupported")
		return false
	}
	for _, name := range []string{"If-Match", "If-None-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_collection_"+operation+"_condition")
			return false
		}
	}
	if depth, present, valid := tusHeader(r, "Depth"); present && (!valid || depth != "infinity" && (operation != "copy" || depth != "0")) {
		fail(w, 400, "invalid_dav_collection_"+operation+"_depth")
		return false
	}
	parts := strings.Split(r.URL.Path, "/")
	base := "/v1/tenants/" + url.PathEscape(parts[3]) + "/partners/" + url.PathEscape(parts[5]) + "/dav/"
	source, err := webdav.VirtualPath(r.URL.EscapedPath(), base)
	if err != nil || source == "/" {
		fail(w, 400, "invalid_dav_collection_"+operation+"_source")
		return false
	}
	if _, err := davCollectionDestination(r, base); err != nil {
		fail(w, 400, "invalid_dav_collection_"+operation+"_destination")
		return false
	}
	return true
}

func davCollectionDestination(r *http.Request, base string) (string, error) {
	value, present, valid := tusHeader(r, "Destination")
	if !present || !valid || len(value) > 8192 || strings.Contains(value, "#") {
		return "", webdav.ErrRequest
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || !strings.HasSuffix(u.Path, "/") {
		return "", webdav.ErrRequest
	}
	if u.IsAbs() {
		if u.Scheme != "https" || !strings.EqualFold(u.Host, r.Host) {
			return "", webdav.ErrRequest
		}
	} else if u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		return "", webdav.ErrRequest
	}
	target, err := webdav.VirtualPath(u.EscapedPath(), base)
	if err != nil || target == "/" {
		return "", webdav.ErrRequest
	}
	return target, nil
}

func (s *Server) davCollectionMove(w http.ResponseWriter, r *http.Request, scope store.Scope, source, base string) {
	target, err := davCollectionDestination(r, base)
	if err != nil {
		fail(w, 400, "invalid_dav_collection_move_destination")
		return
	}
	entry, revision, valid := davNamespaceCondition(r.Header.Get("X-Freightctl-Namespace-Revision"))
	if !valid {
		fail(w, 400, "invalid_dav_namespace_revision")
		return
	}
	command := store.PathCommand{Operation: "move_tree", Path: source, Target: target, ExpectedEntryID: entry, ExpectedRevision: &revision}
	if !davCollectionReplacement(r, &command) {
		fail(w, 400, "invalid_dav_destination_namespace_revision")
		return
	}
	result, err := s.Service.PathCommand(r.Context(), scope, r.Header.Get("Idempotency-Key"), command)
	if errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrExists) {
		fail(w, 412, "dav_collection_move_condition_failed")
		return
	}
	if errors.Is(err, store.ErrLimit) {
		fail(w, 507, "dav_collection_move_requires_smaller_tree")
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
	if command.Replace {
		davCollectionReplaced(w, result)
		return
	}
	w.Header().Set("Location", webdav.Href(base, webdav.Resource{Path: result.Entry.Path, Directory: true}))
	respond(w, 201, map[string]any{"result": result, "namespace_state": "collection-moved-at-commit"})
}

func davCollectionReplacement(r *http.Request, command *store.PathCommand) bool {
	if r.Header.Get("Overwrite") != "T" {
		return true
	}
	entry, revision, valid := davNamespaceCondition(r.Header.Get("X-Freightctl-Destination-Revision"))
	if !valid {
		return false
	}
	command.Replace = true
	command.TargetEntryID = entry
	command.TargetRevision = &revision
	return true
}

func davCollectionReplaced(w http.ResponseWriter, result *store.PathResult) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Freightctl-Namespace-State", "collection-replaced-at-commit")
	w.Header().Set("X-Freightctl-Event-ID", result.Entry.EventID)
	w.Header().Set("X-Freightctl-Changed-Entries", strconv.Itoa(result.Changed))
	w.WriteHeader(http.StatusNoContent)
}
