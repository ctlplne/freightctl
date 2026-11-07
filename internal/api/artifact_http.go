package api

import (
	"io"
	"net/http"
	"time"

	"github.com/ctlplne/freightctl/internal/store"
)

type privateArtifactResponse struct{ http.ResponseWriter }

// ServeContent removes caching metadata from some errors. These responses
// still concern private artifact state,so keep no-store at the actual write.
func (w privateArtifactResponse) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(code)
}
func (w privateArtifactResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func artifactRevisionETag(file *store.File) string {
	return `"freightctl-` + file.ID + `-` + file.SHA256 + `"`
}

// Call only after ordinary authorization,intake and immutable storage checks.
// The ReaderAt rechecks live authority on each bounded read.
func serveArtifactRevision(w http.ResponseWriter, r *http.Request, file *store.File, data io.ReaderAt, disposition string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("X-Content-SHA256", file.SHA256)
	w.Header().Set("X-File-Revision-ID", file.ID)
	w.Header().Set("ETag", artifactRevisionETag(file))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(privateArtifactResponse{w}, r, file.ID, time.Time{}, io.NewSectionReader(data, 0, file.Size))
}
