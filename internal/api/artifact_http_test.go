package api

import (
	"bytes"
	"net/http/httptest"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestArtifactHTTPStrongValidatorPinsExactRevisionForResume(t *testing.T) {
	data := []byte("immutable artifact bytes")
	file := &store.File{ID: "11111111-1111-4111-8111-111111111111", SHA256: secure.Digest(data), Size: int64(len(data))}
	initial := httptest.NewRecorder()
	serveArtifactRevision(initial, httptest.NewRequest("HEAD", "/artifact", nil), file, bytes.NewReader(data), "attachment")
	etag := initial.Header().Get("ETag")
	if etag == "" || etag[0] != '"' || initial.Body.Len() != 0 {
		t.Fatal("artifact has no strong revision validator")
	}
	request := httptest.NewRequest("GET", "/artifact", nil)
	request.Header.Set("Range", "bytes=5-")
	request.Header.Set("If-Range", etag)
	partial := httptest.NewRecorder()
	serveArtifactRevision(partial, request, file, bytes.NewReader(data), "attachment")
	if partial.Code != 206 || !bytes.Equal(partial.Body.Bytes(), data[5:]) || partial.Header().Get("ETag") != etag || partial.Header().Get("X-File-Revision-ID") != file.ID {
		t.Fatal("matching immutable revision did not resume exact bytes")
	}
	// Equal content in a different revision is still a different artifact.
	other := *file
	other.ID = "22222222-2222-4222-8222-222222222222"
	full := httptest.NewRecorder()
	serveArtifactRevision(full, request, &other, bytes.NewReader(data), "attachment")
	if full.Code != 200 || !bytes.Equal(full.Body.Bytes(), data) || full.Header().Get("ETag") == etag || full.Header().Get("Content-Range") != "" {
		t.Fatal("stale revision validator permitted mixed resumed bytes")
	}
}

func TestArtifactHTTPRangeErrorsKeepNoStoreAfterStandardServing(t *testing.T) {
	data := []byte("private bytes")
	file := &store.File{ID: "11111111-1111-4111-8111-111111111111", SHA256: secure.Digest(data), Size: int64(len(data))}
	r := httptest.NewRequest("GET", "/artifact", nil)
	r.Header.Set("Range", "bytes=999-")
	w := httptest.NewRecorder()
	w.Header().Set("Cache-Control", "no-store")
	serveArtifactRevision(w, r, file, bytes.NewReader(data), "attachment")
	if w.Code != 416 || w.Header().Get("Cache-Control") != "no-store" || bytes.Contains(w.Body.Bytes(), data) {
		t.Fatal("range refusal lost private response cache policy or leaked bytes")
	}
}
