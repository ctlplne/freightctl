package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDAVDeliveryRequiresDistinctPinnedWriteCapability(t *testing.T) {
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("constructing approved delivery capability must not contact the peer")
	}))
	client, err := NewDAVDeliveryClient(t.Context(), d, "/private-stage/input.partial", "/inbox/input.dat", 1, strings.Repeat("a", 64), func() error { return nil })
	if err != nil || client == nil {
		t.Fatal("approved DAV delivery profile is unavailable before any external effect")
	}
	defer client.Close()
	read, err := NewHTTPSReadClient(t.Context(), d, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if _, writable := any(read).(interface {
		PutStage(context.Context, *os.File) error
	}); writable {
		t.Fatal("read-only source acquired upload capability")
	}
	for _, pair := range [][2]string{{"/", "/inbox/file"}, {"/stage/file", "/stage/file"}, {"/stage", "/stage/file"}, {"/stage/file", "/stage"}, {"/stage/../file", "/inbox/file"}, {"/.freightctl/token", "/inbox/file"}} {
		if wrong, err := NewDAVDeliveryClient(t.Context(), d, pair[0], pair[1], 1, strings.Repeat("a", 64), func() error { return nil }); err == nil {
			wrong.Close()
			t.Fatal("unbound or ambiguous stage/final paths admitted")
		}
	}
}

func davDeliveryFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "custody")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestDAVDeliveryExactExclusiveStageReadbackAndConditionalPublication(t *testing.T) {
	for _, mode := range []string{"", "basic"} {
		t.Run("authentication="+mode, func(t *testing.T) {
			const stage, final = "/private-stage/input.partial", "/inbox/café #.dat"
			data := bytes.Repeat([]byte("exact immutable custody\n"), 5000)
			var mu sync.Mutex
			files := map[string][]byte{}
			var methods []string
			d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				methods = append(methods, r.Method+" "+r.URL.Path)
				credentialOK := r.Header.Get("Authorization") == "Bearer "+strings.Repeat("d", 64)
				if mode == "basic" {
					u, p, ok := r.BasicAuth()
					credentialOK = ok && u == "writer" && p == strings.Repeat("d", 64)
				}
				if !credentialOK || r.TLS == nil || r.TLS.Version != 0x0304 || r.Header.Get("Accept-Encoding") != "identity" || r.URL.RawQuery != "" || r.Header.Get("Cache-Control") != "no-cache, no-store" {
					t.Error("delivery lost exact TLS,credential,encoding,query or cache policy")
					w.WriteHeader(403)
					return
				}
				switch r.Method {
				case "PUT":
					if r.URL.Path != stage || r.Header.Get("If-None-Match") != "*" || r.ContentLength != int64(len(data)) || len(r.TransferEncoding) != 0 || files[stage] != nil {
						t.Error("stage was not a fixed-length exclusive create")
						w.WriteHeader(412)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil || !bytes.Equal(body, data) {
						t.Error("stage differs from exact source")
						w.WriteHeader(400)
						return
					}
					files[stage] = body
					w.WriteHeader(201)
				case "GET":
					body, found := files[r.URL.Path]
					if !found {
						w.WriteHeader(404)
						return
					}
					w.Header().Set("ETag", `"exact-stage-revision"`)
					w.Write(body)
				case "MOVE":
					u, err := url.Parse(r.Header.Get("Destination"))
					if err != nil || u.Scheme != "https" || u.Host != r.Host || u.Path != final || u.RawQuery != "" || u.Fragment != "" || r.URL.Path != stage || r.Header.Get("Overwrite") != "F" || r.Header.Get("If-Match") != `"exact-stage-revision"` || files[final] != nil || files[stage] == nil {
						t.Error("publication lost exact source ETag or same-authority non-overwrite destination")
						w.WriteHeader(412)
						return
					}
					files[final] = files[stage]
					delete(files, stage)
					w.WriteHeader(201)
				default:
					t.Error("unexpected mutation capability")
					w.WriteHeader(405)
				}
			}))
			if mode == "basic" {
				d.Authentication, d.User = mode, "writer"
				d.PasswordFile, d.PasswordSHA256, d.TokenFile, d.TokenSHA256 = d.TokenFile, d.TokenSHA256, "", ""
			}
			client, err := NewDAVDeliveryClient(t.Context(), d, stage, final, int64(len(data)), Digest(data), func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if client.Publish(t.Context()) == nil {
				t.Fatal("unverified stage could be published")
			}
			file := davDeliveryFile(t, data)
			if _, err = file.Seek(9, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			if err = client.PutStage(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			if err = client.VerifyStage(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = client.Publish(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = client.VerifyFinal(t.Context()); err != nil {
				t.Fatal(err)
			}
			if client.PutStage(t.Context(), file) == nil || client.Publish(t.Context()) == nil || client.VerifyStage(t.Context()) == nil {
				t.Fatal("same capability repeated effects after publication")
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(methods, "|") != "PUT "+stage+"|GET "+stage+"|MOVE "+stage+"|GET "+final || !bytes.Equal(files[final], data) || files[stage] != nil {
				t.Fatal("unexpected effects,stage retention or final bytes")
			}
			if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != 9 {
				t.Fatal("transport changed caller's custody descriptor position")
			}
		})
	}
}

func TestDAVDeliveryNeverPromotesPartialUnboundOrEncodedStage(t *testing.T) {
	data := []byte("exact bytes")
	for _, kind := range []string{"wrong-hash", "short", "extra", "partial", "encoded", "weak-etag", "missing-etag", "duplicate-etag", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			var moves atomic.Int64
			d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					moves.Add(1)
					w.WriteHeader(201)
					return
				}
				body := data
				w.Header().Set("ETag", `"stage"`)
				switch kind {
				case "wrong-hash":
					body = []byte("wrong bytes")
				case "short":
					body = data[:len(data)-1]
				case "extra":
					body = append(append([]byte{}, data...), '!')
				case "partial":
					w.Header().Set("Content-Range", "bytes 0-10/11")
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
				case "weak-etag":
					w.Header().Set("ETag", `W/"stage"`)
				case "missing-etag":
					w.Header().Del("ETag")
				case "duplicate-etag":
					w.Header().Add("ETag", `"other"`)
				case "redirect":
					w.Header().Set("Location", "https://outside.invalid/changed")
					w.WriteHeader(302)
					return
				}
				w.Write(body)
			}))
			client, err := NewDAVDeliveryClient(t.Context(), d, "/stage/file", "/final/file", int64(len(data)), Digest(data), func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if client.VerifyStage(t.Context()) == nil || client.Publish(t.Context()) == nil || moves.Load() != 0 {
				t.Fatal("bad stage acquired publication authority or caused a write")
			}
		})
	}
}

func TestDAVDeliveryRefusesReplacementMultistatusRedirectAndOversizedAcknowledgements(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	for _, operation := range []string{"PUT", "MOVE"} {
		for _, status := range []int{200, 204, 207, 302, 412, 201} {
			t.Run(operation+"/"+http.StatusText(status), func(t *testing.T) {
				data := []byte("exact")
				var writes atomic.Int64
				d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == "GET" {
						w.Header().Set("ETag", `"stage"`)
						w.Write(data)
						return
					}
					writes.Add(1)
					io.Copy(io.Discard, r.Body)
					w.Header().Set("Location", outside.URL+"/changed")
					w.WriteHeader(status)
					if status == 201 {
						w.Write(bytes.Repeat([]byte("x"), (32<<10)+1))
					}
				}))
				client, err := NewDAVDeliveryClient(t.Context(), d, "/stage/file", "/final/file", int64(len(data)), Digest(data), func() error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if operation == "PUT" {
					file := davDeliveryFile(t, data)
					err = client.PutStage(t.Context(), file)
					if client.PutStage(t.Context(), file) == nil {
						t.Fatal("failed stage write automatically repeated")
					}
				} else {
					if err = client.VerifyStage(t.Context()); err != nil {
						t.Fatal(err)
					}
					err = client.Publish(t.Context())
					if client.Publish(t.Context()) == nil {
						t.Fatal("failed publication automatically repeated")
					}
				}
				if err == nil || writes.Load() != 1 || outsideHits.Load() != 0 {
					t.Fatal("unsafe acknowledgement was accepted,replayed or redirected")
				}
			})
		}
	}
}

func TestDAVDeliveryRechecksAuthorityCredentialAndSourceBeforeEffects(t *testing.T) {
	data := []byte("exact bytes")
	var hits atomic.Int64
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("ETag", `"stage"`)
		w.Write(data)
	}))
	var revoked atomic.Bool
	denied := errors.New("fixture authority withdrawn")
	check := func() error {
		if revoked.Load() {
			return denied
		}
		return nil
	}
	client, err := NewDAVDeliveryClient(t.Context(), d, "/stage/file", "/final/file", int64(len(data)), Digest(data), check)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.PutStage(t.Context(), davDeliveryFile(t, []byte("wrong size"))) == nil || hits.Load() != 0 {
		t.Fatal("wrong source descriptor contacted peer")
	}
	if err = client.VerifyStage(t.Context()); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if err = client.Publish(t.Context()); !errors.Is(err, denied) || hits.Load() != 1 {
		t.Fatal("withdrawn authority retained a publication capability")
	}
	revoked.Store(false)
	if err = os.WriteFile(d.TokenFile, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if client.VerifyFinal(t.Context()) == nil || hits.Load() != 1 {
		t.Fatal("changed credential contacted peer under old approval")
	}
	guarded := &davDeliverySource{ctx: t.Context(), check: check, source: io.NewSectionReader(davDeliveryFile(t, data), 0, int64(len(data)))}
	var one [1]byte
	if n, err := guarded.Read(one[:]); n != 1 || err != nil {
		t.Fatal("approved custody stream unavailable")
	}
	revoked.Store(true)
	if n, err := guarded.Read(one[:]); n != 0 || !errors.Is(err, denied) {
		t.Fatal("withdrawn authority kept streaming source bytes")
	}
	var checks atomic.Int64
	duringRead := &davDeliverySource{ctx: t.Context(), check: func() error {
		if checks.Add(1) == 2 {
			return denied
		}
		return nil
	}, source: io.NewSectionReader(davDeliveryFile(t, data), 0, int64(len(data)))}
	if n, err := duringRead.Read(one[:]); n != 0 || !errors.Is(err, denied) || one[0] != 0 || duringRead.read.Load() != 0 {
		t.Fatal("authority withdrawn during source read exposed bytes or counted them as sent")
	}
}

func TestDAVDeliveryCloseInterruptsBlockedAcknowledgement(t *testing.T) {
	entered := make(chan struct{})
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(201)
		w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	client, err := NewDAVDeliveryClient(t.Context(), d, "/stage/file", "/final/file", 1, Digest([]byte("x")), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	file := davDeliveryFile(t, []byte("x"))
	// The source method is pending until the server's complete acknowledgement.
	go func() { result <- client.PutStage(ctx, file) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("bounded stand-in did not reach the pending acknowledgement")
	}
	client.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed client acknowledged an incomplete response")
		}
	case <-ctx.Done():
		t.Fatal("closing delivery capability did not interrupt pending response")
	}
}

func TestDAVDeliveryEmptyCustodyUsesExactZeroLengthAndReadback(t *testing.T) {
	var puts, gets atomic.Int64
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			puts.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) != 0 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				t.Error("empty custody became an unbounded or nonempty request")
			}
			w.WriteHeader(201)
		case "GET":
			gets.Add(1)
			w.Header().Set("ETag", `"empty-stage"`)
			w.WriteHeader(200)
		default:
			t.Error("empty proof performed an unrelated effect")
		}
	}))
	client, err := NewDAVDeliveryClient(t.Context(), d, "/stage/empty", "/final/empty", 0, Digest(nil), func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.PutStage(t.Context(), davDeliveryFile(t, nil)); err != nil {
		t.Fatal(err)
	}
	if err = client.VerifyStage(t.Context()); err != nil || puts.Load() != 1 || gets.Load() != 1 {
		t.Fatal("empty custody did not retain its exact approved hash and size", err)
	}
}
