package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

type davReadStandIn struct {
	response *secure.HTTPSReadResponse
	paths    []string
}

func (s *davReadStandIn) Get(_ context.Context, target string) (*secure.HTTPSReadResponse, error) {
	s.paths = append(s.paths, target)
	return s.response, nil
}
func (*davReadStandIn) Close() error { return nil }

func davReadFixture(data []byte, length int64) (*DAVCollectionPeer, *davReadStandIn) {
	r := &davReadStandIn{response: &secure.HTTPSReadResponse{StatusCode: 200, ContentLength: length, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}}
	return &DAVCollectionPeer{client: r, directory: "/reviewed/inbox"}, r
}

func TestDAVCollectionReadsOnlyExactReviewedPrivateStagingInputs(t *testing.T) {
	check := func() error { return nil }
	manifest := []byte(`{"schema_version":1,"files":[]}`)
	p, peer := davReadFixture(manifest, int64(len(manifest)))
	actual, err := p.ReadManifest(t.Context(), "batch.ready.json", check)
	if err != nil || !bytes.Equal(actual, manifest) || len(peer.paths) != 1 || peer.paths[0] != "/reviewed/inbox/batch.ready.json" {
		t.Fatal("reviewed DAV manifest path or exact bytes changed", err)
	}
	data := bytes.Repeat([]byte("source stays untouched\n"), 4000)
	p, peer = davReadFixture(data, int64(len(data)))
	var staging bytes.Buffer
	if err = p.CopyVerified(t.Context(), "input.dat", int64(len(data)), secure.Digest(data), &staging, check); err != nil || !bytes.Equal(staging.Bytes(), data) || len(peer.paths) != 1 || peer.paths[0] != "/reviewed/inbox/input.dat" {
		t.Fatal("exact DAV read failed or selected another source", err)
	}
	for _, name := range []string{"../input.dat", "input/name", "https://outside.invalid/data", "input?other", "input#fragment"} {
		p, peer = davReadFixture(data, int64(len(data)))
		if err = p.CopyVerified(t.Context(), name, int64(len(data)), secure.Digest(data), &staging, check); err == nil || len(peer.paths) != 0 {
			t.Fatal("producer name redirected a source read")
		}
	}
}

func TestDAVCollectionRefusesRedirectPartialEncodedAndChangedSources(t *testing.T) {
	data := []byte("exact source")
	check := func() error { return nil }
	for _, change := range []func(*secure.HTTPSReadResponse){
		func(r *secure.HTTPSReadResponse) {
			r.StatusCode = 302
			r.Header.Set("Location", "https://outside.invalid/")
		},
		func(r *secure.HTTPSReadResponse) { r.StatusCode = 206 },
		func(r *secure.HTTPSReadResponse) { r.Header.Set("Content-Range", "bytes 0-11/12") },
		func(r *secure.HTTPSReadResponse) { r.Header.Set("Content-Encoding", "gzip") },
		func(r *secure.HTTPSReadResponse) { r.ContentLength++ },
	} {
		p, peer := davReadFixture(data, int64(len(data)))
		change(peer.response)
		var staging bytes.Buffer
		if err := p.CopyVerified(t.Context(), "input.dat", int64(len(data)), secure.Digest(data), &staging, check); err == nil || staging.Len() != 0 {
			t.Fatal("non-exact response entered staging")
		}
	}
	for _, body := range [][]byte{data[:len(data)-1], append(append([]byte{}, data...), 'x'), bytes.Repeat([]byte("x"), len(data))} {
		p, _ := davReadFixture(body, -1)
		var staging bytes.Buffer
		if err := p.CopyVerified(t.Context(), "input.dat", int64(len(data)), secure.Digest(data), &staging, check); err == nil {
			t.Fatal("truncated,extended or digest-mismatched stream was accepted")
		}
	}
	p, _ := davReadFixture(bytes.Repeat([]byte("x"), (32<<10)+1), -1)
	if data, err := p.ReadManifest(t.Context(), "batch.ready.json", check); err == nil || data != nil {
		t.Fatal("oversized manifest escaped its original metadata bound")
	}
}

type davWithdrawOnRead struct {
	reader io.Reader
	deny   *bool
}

func (r davWithdrawOnRead) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	*r.deny = true
	return n, err
}
func (davWithdrawOnRead) Close() error { return nil }

func TestDAVCollectionRechecksAuthorityBeforeEachStagingWrite(t *testing.T) {
	data := []byte("not authorized for local staging after withdrawal")
	p, peer := davReadFixture(data, int64(len(data)))
	deny := false
	peer.response.Body = davWithdrawOnRead{reader: strings.NewReader(string(data)), deny: &deny}
	withdrawn := errors.New("stand-in authority withdrawn")
	var staging bytes.Buffer
	err := p.CopyVerified(t.Context(), "input.dat", int64(len(data)), secure.Digest(data), &staging, func() error {
		if deny {
			return withdrawn
		}
		return nil
	})
	if !errors.Is(err, withdrawn) || staging.Len() != 0 {
		t.Fatal("a read completed after withdrawal and still entered local staging")
	}
}
