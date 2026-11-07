package api

import (
	"errors"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/webdav"
)

const davReadMethods = "OPTIONS, PROPFIND, GET, HEAD"

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
		resource := webdav.Resource{Path: p.Entry.Path, Directory: p.Entry.Kind == "dir", Modified: p.Entry.Modified, Size: p.Entry.Size}
		if p.File != nil {
			resource.ETag = artifactRevisionETag(p.File)
		}
		resources = append(resources, resource)
	}
	body, err := webdav.Multistatus(base, resources, selection)
	if err != nil {
		fail(w, 503, "dav_properties_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(207)
	_, _ = w.Write(body)
}
