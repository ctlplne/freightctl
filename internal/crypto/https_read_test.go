package crypto

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func httpsReadFixture(t *testing.T, handler http.Handler) (HTTPSReadDestination, *httptest.Server) {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	private := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	token := bytes.Repeat([]byte("d"), 64)
	d := HTTPSReadDestination{Address: strings.TrimPrefix(server.URL, "https://"), ServerName: "example.com", CAFile: filepath.Join(private, "ca.pem"), CASHA256: Digest(ca), TokenFile: filepath.Join(private, "token"), TokenSHA256: Digest(token)}
	for p, data := range map[string][]byte{d.CAFile: ca, d.TokenFile: token} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return d, server
}

func TestHTTPSReadPinsNativeEndpointAndHasNoAmbientAuthority(t *testing.T) {
	d := HTTPSReadDestination{Address: "127.0.0.1:443", ServerName: "localhost", CAFile: filepath.Join(t.TempDir(), "ca"), CASHA256: strings.Repeat("a", 64), TokenFile: filepath.Join(t.TempDir(), "token"), TokenSHA256: strings.Repeat("b", 64)}
	if ValidateHTTPSReadDestination(d) != nil {
		t.Fatal("exact numeric endpoint/reference shape refused")
	}
	for _, change := range []func(*HTTPSReadDestination){
		func(d *HTTPSReadDestination) { d.Address = "source.invalid:443" },
		func(d *HTTPSReadDestination) { d.Address = "0.0.0.0:443" },
		func(d *HTTPSReadDestination) { d.Address = "224.0.0.1:443" },
		func(d *HTTPSReadDestination) { d.Address = "[ff00::1]:443" },
		func(d *HTTPSReadDestination) { d.Address = "127.0.0.1:0443" },
		func(d *HTTPSReadDestination) { d.Address = "127.0.0.1:65536" },
		func(d *HTTPSReadDestination) { d.ServerName = "outside.invalid/path" },
		func(d *HTTPSReadDestination) { d.ServerName = "outside.invalid\r\nOther: value" },
		func(d *HTTPSReadDestination) { d.CAFile = "relative.pem" },
		func(d *HTTPSReadDestination) { d.TokenSHA256 = strings.Repeat("B", 64) },
	} {
		mutated := d
		change(&mutated)
		if ValidateHTTPSReadDestination(mutated) == nil {
			t.Fatal("ambiguous HTTPS source configuration admitted")
		}
	}
}

func TestHTTPSReadVerifiedTLSExactBytesAndCurrentAuthority(t *testing.T) {
	data := bytes.Repeat([]byte("inert pinned source\n"), 5000)
	var hits, malformed atomic.Int64
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" || r.URL.Path != "/remote/source.dat" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("d", 64) || r.Header.Get("Accept-Encoding") != "identity" || r.TLS == nil || r.TLS.Version != 0x0304 {
			malformed.Add(1)
		}
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
	client, err := NewHTTPSReadClient(t.Context(), d, check)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Get(t.Context(), "/remote/source.dat")
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(received, data) || response.StatusCode != 200 || malformed.Load() != 0 || hits.Load() != 1 {
		t.Fatal("verified read changed bytes,request shape or TLS policy")
	}
	response, err = client.Get(t.Context(), "/remote/source.dat")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var first [1]byte
	if _, err = io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	if n, err := response.Body.Read(first[:]); n != 0 || !errors.Is(err, denied) {
		t.Fatal("withdrawn authority retained an active byte stream")
	}
	if _, err = client.Get(t.Context(), "/remote/source.dat"); !errors.Is(err, denied) || hits.Load() != 2 {
		t.Fatal("withdrawn authority contacted the peer again")
	}
}

func TestHTTPSReadNeverFollowsRedirectOrAcceptsWrongTLSIdentity(t *testing.T) {
	var outsideHits atomic.Int64
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideHits.Add(1) }))
	defer outside.Close()
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", outside.URL+"/steal")
		w.WriteHeader(302)
	}))
	check := func() error { return nil }
	client, err := NewHTTPSReadClient(t.Context(), d, check)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(t.Context(), "/redirect")
	if err != nil || response.StatusCode != 302 {
		t.Fatal("original redirect was not preserved for protocol refusal")
	}
	response.Body.Close()
	client.Close()
	if outsideHits.Load() != 0 {
		t.Fatal("source redirect changed recipient or leaked credentials")
	}
	d.ServerName = "wrong.invalid"
	wrong, err := NewHTTPSReadClient(t.Context(), d, check)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err = wrong.Get(t.Context(), "/redirect"); !errors.Is(err, ErrHTTPSRead) || outsideHits.Load() != 0 {
		t.Fatal("wrong TLS identity was accepted")
	}
}

func TestHTTPSReadCloseInterruptsAnActiveResponse(t *testing.T) {
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.Write([]byte("a"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, err := NewHTTPSReadClient(ctx, d, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Get(ctx, "/blocked")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var first [1]byte
	if _, err = io.ReadFull(response.Body, first[:]); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := response.Body.Read(first[:]); result <- err }()
	client.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("closed client completed an unreceived byte")
		}
	case <-ctx.Done():
		t.Fatal("closing source transport did not interrupt an active response")
	}
}

func TestHTTPSReadReopensApprovedCredentialAndRejectsChangedTrustBeforeContact(t *testing.T) {
	var hits atomic.Int64
	d, _ := httpsReadFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("inert"))
	}))
	check := func() error { return nil }
	wrong := d
	wrong.CASHA256 = strings.Repeat("a", 64)
	if _, err := NewHTTPSReadClient(t.Context(), wrong, check); !errors.Is(err, ErrHTTPSRead) || hits.Load() != 0 {
		t.Fatal("changed pinned CA was accepted or contacted the source")
	}
	client, err := NewHTTPSReadClient(t.Context(), d, check)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	response, err := client.Get(t.Context(), "/source")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if hits.Load() != 1 {
		t.Fatal("approved credential did not select exactly one source read")
	}
	if err = os.WriteFile(d.TokenFile, []byte("changed-protected-fixture-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Get(t.Context(), "/source"); !errors.Is(err, ErrHTTPSRead) || hits.Load() != 1 {
		t.Fatal("changed credential bytes reused the old approval or contacted the source")
	}
}
