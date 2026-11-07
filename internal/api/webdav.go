package api

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

const davDirectoryMethods = "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, PROPPATCH, MOVE, DELETE"
const davReadMethods = davDirectoryMethods + ", COPY"

// Validate before ServeMux can clean a path into a different namespace name or
// redirect it. This initial profile uses explicit bearer credentials only.
func prepareDAVRequest(w http.ResponseWriter, r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 7 || parts[1] != "v1" || parts[2] != "tenants" || parts[4] != "partners" || parts[6] != "dav" {
		return true
	}
	if r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="freightctl"`)
		failure(w, store.ErrUnauthorized)
		return false
	}
	base := "/v1/tenants/" + url.PathEscape(parts[3]) + "/partners/" + url.PathEscape(parts[5]) + "/dav/"
	if _, err := webdav.VirtualPath(r.URL.EscapedPath(), base); err != nil || r.URL.RawQuery != "" || r.URL.ForceQuery {
		fail(w, 400, "invalid_dav_virtual_path")
		return false
	}
	// A known metadata condition must never be silently discarded by an
	// adapter that implements only byte or absence conditions.
	switch r.Method {
	case http.MethodPut, "MKCOL", "MOVE", "COPY", http.MethodDelete:
		collectionCondition := (r.Method == "MOVE" || r.Method == http.MethodDelete) && strings.HasSuffix(r.URL.Path, "/")
		if !collectionCondition {
			if _, present, _ := tusHeader(r, "X-Freightctl-Namespace-Revision"); present {
				fail(w, 400, "unsupported_dav_namespace_condition")
				return false
			}
		}
	}
	if r.Method == http.MethodPut {
		return davCreateInput(w, r)
	}
	if r.Method == "MKCOL" {
		return davCollectionInput(w, r)
	}
	if r.Method == "MOVE" {
		return davMoveInput(w, r)
	}
	if r.Method == "COPY" {
		return davFileMappingInput(w, r, "copy")
	}
	if r.Method == http.MethodDelete {
		return davDeleteInput(w, r)
	}
	if r.Method == "PROPPATCH" {
		return davPropertyMutationInput(w, r)
	}
	return true
}

func davCollectionInput(w http.ResponseWriter, r *http.Request) bool {
	key, _, valid := tusHeader(r, "Idempotency-Key")
	if !valid || key == "" {
		fail(w, 400, "dav_collection_requires_original_key")
		return false
	}
	if r.ContentLength != 0 {
		fail(w, 415, "dav_collection_body_unsupported")
		return false
	}
	condition, present, valid := tusHeader(r, "If-None-Match")
	if present && (!valid || condition != "*") {
		fail(w, 400, "invalid_dav_collection_condition")
		return false
	}
	for _, name := range []string{"If-Match", "If-Unmodified-Since", "If-Modified-Since", "If", "Content-Range"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_dav_collection_condition")
			return false
		}
	}
	return true
}

func davCreateInput(w http.ResponseWriter, r *http.Request) bool {
	condition, present, valid := tusHeader(r, "If-None-Match")
	match, hasMatch, matchValid := tusHeader(r, "If-Match")
	if !present && !hasMatch {
		fail(w, 428, "dav_create_requires_if_none_match_star")
		return false
	}
	_, hasDAVIf, _ := tusHeader(r, "If")
	_, hasRange, _ := tusHeader(r, "Content-Range")
	_, hasUnmodified, _ := tusHeader(r, "If-Unmodified-Since")
	_, hasModified, _ := tusHeader(r, "If-Modified-Since")
	_, _, exactMatch := davFileTag(match)
	if present && (!valid || condition != "*" || hasMatch) || hasMatch && (!matchValid || !exactMatch || present) || hasDAVIf || hasRange || hasUnmodified || hasModified {
		fail(w, 400, "invalid_dav_create_condition")
		return false
	}
	if r.ContentLength < 0 {
		fail(w, 411, "dav_create_requires_content_length")
		return false
	}
	key, _, keyValid := tusHeader(r, "Idempotency-Key")
	digest, _, digestValid := tusHeader(r, "X-Content-SHA256")
	if !keyValid || key == "" || !digestValid || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		fail(w, 400, "invalid_dav_create_contract")
		return false
	}
	return true
}

func (s *Server) davRead(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil || r.Header.Get("Authorization") == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="freightctl"`)
		failure(w, store.ErrUnauthorized)
		return
	}
	base := "/v1/tenants/" + url.PathEscape(identity.Tenant) + "/partners/" + url.PathEscape(identity.Partner) + "/dav/"
	virtual, err := webdav.VirtualPath(r.URL.EscapedPath(), base)
	if err != nil {
		fail(w, 400, "invalid_dav_virtual_path")
		return
	}
	if r.Method == "PROPPATCH" {
		s.davPropertyMutation(w, r, identity, virtual, base)
		return
	}
	if r.Method == "MOVE" {
		s.davMove(w, r, identity, virtual, base)
		return
	}
	if r.Method == "COPY" {
		s.davCopy(w, r, identity, virtual, base)
		return
	}
	if r.Method == http.MethodDelete {
		s.davDelete(w, r, identity, virtual)
		return
	}
	if r.Method == "MKCOL" {
		result, err := s.Service.MakeDirectoryIfAbsent(r.Context(), identity, r.Header.Get("Idempotency-Key"), virtual)
		if errors.Is(err, store.ErrExists) {
			code := 405
			if r.Header.Get("If-None-Match") == "*" {
				code = 412
			}
			w.Header().Set("Allow", davReadMethods)
			fail(w, code, "dav_collection_target_exists")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			fail(w, 409, "dav_parent_collection_required")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		status, state := 201, "created-at-commit"
		if result.Replayed {
			status, state = 200, "not-asserted-original-receipt"
		} else {
			w.Header().Set("Location", webdav.Href(base, webdav.Resource{Path: result.Entry.Path, Directory: true}))
		}
		respond(w, status, map[string]any{"result": result, "namespace_state": state})
		return
	}
	if r.Method == http.MethodPut {
		if virtual == "/" || strings.HasSuffix(r.URL.Path, "/") {
			fail(w, 400, "dav_create_requires_file_name")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, s.Service.MaxFile+1)
		target := custody.UploadTarget{Path: virtual, RequireAbsent: true}
		if match := r.Header.Get("If-Match"); match != "" {
			id, digest, valid := davFileTag(match)
			if !valid {
				fail(w, 400, "invalid_dav_replace_revision")
				return
			}
			target.RequireAbsent = false
			target.MatchFile = &custody.FileCondition{ID: id, SHA256: digest}
		}
		file, replayed, err := s.Service.AcceptAt(r.Context(), identity, r.Header.Get("Idempotency-Key"), r.ContentLength, r.Header.Get("X-Content-SHA256"), r.Body, target)
		if target.MatchFile != nil && (errors.Is(err, store.ErrRevision) || errors.Is(err, store.ErrNotFound)) {
			fail(w, 412, "dav_replace_condition_failed")
			return
		}
		if errors.Is(err, custody.ErrNamespaceFileProfile) {
			w.Header().Set("Allow", davDirectoryMethods)
			fail(w, 405, "dav_file_replace_profile_only")
			return
		}
		if errors.Is(err, store.ErrExists) {
			fail(w, 412, "dav_resource_already_exists")
			return
		}
		if err != nil {
			failure(w, err)
			return
		}
		acceptance := custody.Acceptance(file)
		status := 201
		namespaceState := "published-at-commit"
		if target.MatchFile != nil {
			status, namespaceState = 200, "replaced-at-commit"
		}
		if acceptance == "durable-held-pending-checks-and-release" {
			status = 202
		}
		if status == 202 {
			namespaceState = "not-published-at-acceptance"
		}
		if replayed {
			status = 200
			namespaceState = "not-asserted-original-receipt"
		}
		// A held receipt is not a DAV publication or current-resource validator.
		if (status == 201 || target.MatchFile != nil && status == 200) && !replayed {
			w.Header().Set("ETag", artifactRevisionETag(file))
		}
		w.Header().Set("X-Freightctl-Acceptance", acceptance)
		respond(w, status, map[string]any{"file": file, "replayed": replayed, "acceptance": acceptance, "namespace_state": namespaceState})
		return
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		file, data, err := s.Service.OpenPathReader(r.Context(), identity, virtual)
		if err != nil {
			failure(w, err)
			return
		}
		defer data.Close()
		serveArtifactRevision(w, r, file, data, mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(virtual)}))
		return
	}
	if r.Method != "PROPFIND" && r.Method != http.MethodOptions {
		if _, err = s.Service.DB.Identity(r.Context(), identity); err != nil {
			failure(w, err)
			return
		}
		w.Header().Set("Allow", davReadMethods)
		fail(w, 405, "dav_read_profile_only")
		return
	}
	selection := webdav.Selection{All: true}
	depth := "0"
	if r.Method == "PROPFIND" {
		value, present, valid := tusHeader(r, "Depth")
		if !valid || present && value != "0" && value != "1" && value != "infinity" {
			fail(w, 400, "invalid_dav_depth")
			return
		}
		depth = value
		if !present {
			depth = "infinity"
		}
		if depth == "0" || depth == "1" {
			if r.ContentLength != 0 {
				media, parameters, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if mediaErr != nil || (media != "application/xml" && media != "text/xml") || parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8") {
					fail(w, 415, "dav_utf8_xml_required")
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, webdav.MaxRequestBytes)
			selection, err = webdav.ParseSelection(r.Body)
			if err != nil {
				fail(w, 400, "invalid_dav_property_request")
				return
			}
		}
	}
	properties, err := s.Service.ReadNamespaceProperties(r.Context(), identity, virtual, depth == "1")
	if errors.Is(err, store.ErrLimit) {
		fail(w, 507, "dav_collection_requires_smaller_scope")
		return
	}
	if err != nil {
		failure(w, err)
		return
	}
	if depth == "infinity" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?><error xmlns="DAV:"><propfind-finite-depth/></error>`))
		return
	}
	if r.Method == http.MethodOptions {
		w.Header().Set("Allow", davReadMethods)
		// No DAV compliance class is advertised by this partial read profile.
		w.WriteHeader(204)
		return
	}
	resources := make([]webdav.Resource, 0, len(properties))
	for _, p := range properties {
		resource := webdav.Resource{Path: p.Entry.Path, Directory: p.Entry.Kind == "dir", Modified: p.Entry.Modified, Size: p.Entry.Size, EntryID: p.Entry.ID, Revision: p.Entry.Revision, Properties: p.Properties}
		if p.File != nil {
			resource.ETag = artifactRevisionETag(p.File)
		}
		resources = append(resources, resource)
	}
	body, err := webdav.Multistatus(base, resources, selection)
	if errors.Is(err, webdav.ErrResponseLimit) {
		fail(w, 507, "dav_properties_require_smaller_scope")
		return
	}
	if err != nil {
		fail(w, 503, "dav_properties_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(207)
	_, _ = w.Write(body)
}
