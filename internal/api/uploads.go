package api

import (
	"io"
	"net/http"
	"strconv"

	"github.com/ctlplne/freightctl/internal/custody"
)

func (s *Server) listUploads(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil {
			fail(w, 400, "invalid_page_limit")
			return
		}
	}
	result, err := s.Service.ListUploads(r.Context(), identity, r.URL.Query().Get("after"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}

func (s *Server) createUpload(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var input custody.CreateUpload
	if err = boundedControlInput(w, r, 16<<10, &input); err != nil {
		fail(w, 400, "invalid_upload_session")
		return
	}
	result, err := s.Service.CreateUpload(r.Context(), identity, r.Header.Get("Idempotency-Key"), input)
	if err != nil {
		failure(w, err)
		return
	}
	status := http.StatusCreated
	if result.Replayed {
		status = http.StatusOK
	}
	respond(w, status, result)
}
func (s *Server) uploadStatus(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	result, err := s.Service.UploadStatus(r.Context(), identity, r.PathValue("upload"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
func (s *Server) appendUpload(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		failure(w, custody.ErrInput)
		return
	}
	size, err := strconv.ParseInt(r.Header.Get("X-File-Size"), 10, 64)
	if err != nil || r.ContentLength >= 0 && r.ContentLength != size {
		failure(w, custody.ErrInput)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, custody.MaxUploadChunk+1)
	result, err := s.Service.AppendUpload(r.Context(), identity, r.PathValue("upload"), r.Header.Get("Idempotency-Key"), offset, size, r.Header.Get("X-Content-SHA256"), r.Body)
	if err != nil {
		failure(w, err)
		return
	}
	w.Header().Set("Upload-Offset", strconv.FormatInt(result.Upload.Offset, 10))
	respond(w, 200, result)
}
func (s *Server) completeUpload(w http.ResponseWriter, r *http.Request) { s.uploadAction(w, r, false) }
func (s *Server) abortUpload(w http.ResponseWriter, r *http.Request)    { s.uploadAction(w, r, true) }
func (s *Server) uploadAction(w http.ResponseWriter, r *http.Request, abort bool) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	// These actions have no request body; do not silently ignore extra commands.
	r.Body = http.MaxBytesReader(w, r.Body, 1)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) != 0 {
		failure(w, custody.ErrInput)
		return
	}
	var result *custody.UploadResult
	if abort {
		result, err = s.Service.AbortUpload(r.Context(), identity, r.PathValue("upload"), r.Header.Get("Idempotency-Key"))
	} else {
		result, err = s.Service.CompleteUpload(r.Context(), identity, r.PathValue("upload"), r.Header.Get("Idempotency-Key"))
	}
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
