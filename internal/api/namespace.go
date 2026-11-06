package api

import (
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func (s *Server) identity(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	info, err := s.Service.DB.Identity(r.Context(), identity)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, info)
}
func (s *Server) pathCommand(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	var command store.PathCommand
	if err = boundedControlInput(w, r, 16<<10, &command); err != nil {
		fail(w, 400, "invalid_path_command")
		return
	}
	result, err := s.Service.PathCommand(r.Context(), identity, r.Header.Get("Idempotency-Key"), command)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, result)
}
func (s *Server) statPath(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	entry, err := s.Service.StatPath(r.Context(), identity, r.URL.Query().Get("path"))
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, entry)
}
func (s *Server) listPath(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil {
			fail(w, 400, "invalid_page_limit")
			return
		}
	}
	page, err := s.Service.ListPath(r.Context(), identity, r.URL.Query().Get("path"), r.URL.Query().Get("after"), limit)
	if err != nil {
		failure(w, err)
		return
	}
	respond(w, 200, page)
}
func (s *Server) downloadPath(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	file, data, err := s.Service.OpenPathReader(r.Context(), identity, r.URL.Query().Get("path"))
	if err != nil {
		requestFailure(w, r, err)
		return
	}
	defer data.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(r.URL.Query().Get("path"))}))
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.Header().Set("X-File-Revision-ID", file.ID)
	http.ServeContent(w, r, file.ID, time.Time{}, io.NewSectionReader(data, 0, file.Size))
}
func (s *Server) uploadPath(w http.ResponseWriter, r *http.Request) {
	identity, err := scope(r)
	if err != nil {
		failure(w, err)
		return
	}
	size, err := strconv.ParseInt(r.Header.Get("X-File-Size"), 10, 64)
	if err != nil {
		failure(w, custody.ErrInput)
		return
	}
	if r.ContentLength >= 0 && r.ContentLength != size {
		failure(w, custody.ErrInput)
		return
	}
	target := custody.UploadTarget{Path: r.URL.Query().Get("path")}
	if value := r.Header.Get("If-Match-Revision"); value != "" {
		revision, err := strconv.ParseInt(value, 10, 64)
		if err != nil || revision < 1 {
			fail(w, 400, "invalid_expected_revision")
			return
		}
		target.ExpectedRevision = &revision
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.Service.MaxFile+1)
	file, replay, err := s.Service.AcceptAt(r.Context(), identity, r.Header.Get("Idempotency-Key"), size, r.Header.Get("X-Content-SHA256"), r.Body, target)
	if err != nil {
		failure(w, err)
		return
	}
	status := 201
	if replay {
		status = 200
	}
	respond(w, status, map[string]any{"file": file, "replayed": replay, "acceptance": custody.Acceptance(file)})
}
