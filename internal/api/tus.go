package api

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func tusResourcePath(path string) bool {
	p := strings.Split(path, "/")
	return len(p) == 9 && p[1] == "v1" && p[2] == "tenants" && p[4] == "partners" && p[6] == "tus" && p[7] == "uploads"
}

func tusHeader(r *http.Request, name string) (string, bool, bool) {
	var values []string
	present := false
	for key, v := range r.Header {
		if strings.EqualFold(key, name) {
			present = true
			values = append(values, v...)
		}
	}
	if !present {
		return "", false, true
	}
	if len(values) != 1 || values[0] == "" {
		return "", true, false
	}
	return values[0], true, true
}

// Rewrite only this protocol's URL family BEFORE cookie CSRF decides whether
// the request mutates state. A GET carrying a PATCH override is still a write.
func prepareTusRequest(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if !tusResourcePath(r.URL.Path) {
		return r, true
	}
	w.Header().Set("Tus-Resumable", "1.0.0")
	if method, present, valid := tusHeader(r, "X-HTTP-Method-Override"); present {
		if !valid || (method != "HEAD" && method != "PATCH" && method != "OPTIONS") {
			fail(w, 400, "invalid_tus_method_override")
			return r, false
		}
		r = r.Clone(r.Context())
		r.Method = method
		r.Header.Del("X-HTTP-Method-Override")
	}
	if r.Method != "OPTIONS" {
		if version, _, valid := tusHeader(r, "Tus-Resumable"); !valid || version != "1.0.0" {
			w.Header().Set("Tus-Version", "1.0.0")
			fail(w, 412, "unsupported_tus_version")
			return r, false
		}
	}
	if r.Method != "HEAD" && r.Method != "PATCH" && r.Method != "OPTIONS" {
		w.Header().Set("Allow", "HEAD, PATCH, OPTIONS")
		fail(w, 405, "unsupported_tus_method")
		return r, false
	}
	return r, true
}

func tusOffset(raw string) (int64, error) {
	if raw == "" || len(raw) > 19 {
		return 0, custody.ErrInput
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, custody.ErrInput
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, custody.ErrInput
	}
	return value, nil
}

func tusCheckpointHeaders(w http.ResponseWriter, u *custody.UploadView) {
	w.Header().Set("Upload-Offset", strconv.FormatInt(u.Offset, 10))
	w.Header().Set("Upload-Length", strconv.FormatInt(u.ExpectedSize, 10))
	w.Header().Set("X-Freightctl-Acceptance", "durable-checkpoint-only")
	if u.State == "completed" {
		w.Header().Set("X-Freightctl-Acceptance", u.Acceptance)
		w.Header().Set("X-Freightctl-File-Revision", u.FileID)
	}
}

func (s *Server) tusCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		fail(w, 400, "invalid_tus_control")
		return
	}
	for _, name := range []string{"Upload-Concat", "Upload-Defer-Length", "Upload-Metadata", "Upload-Checksum"} {
		if _, present, _ := tusHeader(r, name); present {
			fail(w, 400, "unsupported_tus_extension")
			return
		}
	}
	var offset int64
	if r.Method == "PATCH" {
		content, present, valid := tusHeader(r, "Content-Type")
		media, parameters, err := mime.ParseMediaType(content)
		if !present || !valid || err != nil || media != "application/offset+octet-stream" || len(parameters) != 0 {
			fail(w, 415, "invalid_tus_media_type")
			return
		}
		raw, present, valid := tusHeader(r, "Upload-Offset")
		offset, err = tusOffset(raw)
		if !present || !valid || err != nil {
			fail(w, 400, "invalid_tus_offset")
			return
		}
		if r.ContentLength > custody.MaxUploadChunk {
			fail(w, 413, "tus_chunk_too_large")
			return
		}
	}
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	id := r.PathValue("upload")
	if !store.ValidID(id) {
		fail(w, 404, "not_found")
		return
	}
	if r.Method == "HEAD" || r.Method == "OPTIONS" {
		u, err := s.Service.UploadStatus(r.Context(), identity, id)
		if err != nil {
			failure(w, err)
			return
		}
		if u.State == "aborted" || u.State == "rejected" {
			fail(w, 410, "tus_resource_gone")
			return
		}
		if r.Method == "OPTIONS" {
			w.Header().Set("Tus-Version", "1.0.0")
			w.Header().Set("Tus-Max-Size", strconv.FormatInt(s.Service.MaxFile, 10))
			w.WriteHeader(204)
			return
		}
		tusCheckpointHeaders(w, u)
		w.WriteHeader(200)
		return
	}
	// Metadata/current destination authority precedes the bounded body read.
	u, err := s.Service.WritableUploadStatus(r.Context(), identity, id)
	if err != nil {
		failure(w, err)
		return
	}
	if offset != u.Offset {
		fail(w, 409, "tus_offset_conflict")
		return
	}
	maximum := min(custody.MaxUploadChunk, u.ExpectedSize-offset)
	if r.ContentLength > maximum {
		fail(w, 400, "invalid_tus_chunk_length")
		return
	}
	// One existing API slot holds at most one existing8MiB chunk. The body is
	// hashed as received,then the ordinary service independently hashes staging.
	allocation := maximum + 1
	if r.ContentLength >= 0 {
		allocation = r.ContentLength + 1
	}
	buffer := make([]byte, int(allocation))
	defer clear(buffer)
	r.Body = http.MaxBytesReader(w, r.Body, maximum)
	n, readErr := io.ReadFull(r.Body, buffer)
	var overflow *http.MaxBytesError
	if errors.As(readErr, &overflow) {
		fail(w, 413, "tus_chunk_too_large")
		return
	}
	if readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		fail(w, 400, "invalid_tus_chunk_length")
		return
	}
	size := int64(n)
	if r.ContentLength >= 0 && size != r.ContentLength || size < custody.MinUploadChunk && size != 0 && offset+size != u.ExpectedSize {
		fail(w, 400, "invalid_tus_chunk_length")
		return
	}
	if size == 0 {
		tusCheckpointHeaders(w, u)
		w.WriteHeader(204)
		return
	}
	data := buffer[:n]
	digest := secure.Digest(data)
	key := "tus:" + secure.Digest([]byte(id+":"+strconv.FormatInt(offset, 10)+":"+strconv.FormatInt(size, 10)+":"+digest))
	result, err := s.Service.AppendUploadAtCurrentOffset(r.Context(), identity, id, key, offset, size, digest, bytes.NewReader(data))
	if err != nil {
		failure(w, err)
		return
	}
	if result.Upload.Offset != offset+size {
		failure(w, store.ErrIsolation)
		return
	}
	tusCheckpointHeaders(w, &result.Upload)
	w.WriteHeader(204)
}
