package crypto

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"

	"github.com/ctlplne/freightctl/internal/vpath"
)

var ErrDAVDelivery = errors.New("DAV delivery identity,authority or protocol acknowledgement failed")

// DAVDeliveryClient binds one exact source size/hash and two approved paths.
// It has no arbitrary method,header,recipient,DELETE or overwrite capability.
// This transport cannot authorize a send:the durable worker must commit its
// publishing intent and retain ambiguity before any call that may write bytes.
type DAVDeliveryClient struct {
	read              *HTTPSReadClient
	stage, final      string
	size              int64
	digest            string
	mu                sync.Mutex
	stored, published bool
	stageETag         string
}

func NewDAVDeliveryClient(ctx context.Context, d HTTPSReadDestination, stage, final string, size int64, digest string, check func() error) (*DAVDeliveryClient, error) {
	for _, p := range []string{stage, final} {
		canonical, err := vpath.Canonical(p)
		if err != nil || canonical != p || p == "/" || vpath.ControlPath(p) {
			return nil, ErrDAVDelivery
		}
	}
	if vpath.Within(stage, final) || vpath.Within(final, stage) || size < 0 || !httpsReadDigest(digest) {
		return nil, ErrDAVDelivery
	}
	read, err := NewHTTPSReadClient(ctx, d, check)
	if err != nil {
		return nil, errors.Join(ErrDAVDelivery, err)
	}
	return &DAVDeliveryClient{read: read, stage: stage, final: final, size: size, digest: digest}, nil
}

// Close does not take the operation mutex:it must interrupt a blocked response.
func (c *DAVDeliveryClient) Close() error { return c.read.Close() }

type davDeliverySource struct {
	ctx    context.Context
	check  func() error
	source *io.SectionReader
	read   atomic.Int64
	closed atomic.Bool
}

func (s *davDeliverySource) Read(data []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if err := s.check(); err != nil {
		return 0, err
	}
	n, err := s.source.Read(data[:min(len(data), 32<<10)])
	check := errors.Join(s.ctx.Err(), s.check())
	if s.closed.Load() {
		check = errors.Join(check, io.ErrClosedPipe)
	}
	if check != nil {
		Clear(data[:n])
		return 0, check
	}
	s.read.Add(int64(n))
	return n, err
}

func (s *davDeliverySource) Close() error { s.closed.Store(true); return nil }

func davDeliveryHeaders() http.Header {
	return http.Header{"Cache-Control": {"no-cache, no-store"}, "Pragma": {"no-cache"}}
}

// PutStage attempts exclusive creation once. A failure says nothing about
// whether the receiver retained bytes. No automatic resend or cleanup follows.
// Caller keeps ownership of the already verified immutable custody descriptor.
func (c *DAVDeliveryClient) PutStage(ctx context.Context, file *os.File) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stored || c.published || file == nil {
		return ErrDAVDelivery
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != c.size {
		return ErrDAVDelivery
	}
	c.stored = true
	c.stageETag = ""
	source := &davDeliverySource{ctx: ctx, check: c.read.check, source: io.NewSectionReader(file, 0, c.size)}
	headers := davDeliveryHeaders()
	headers.Set("If-None-Match", "*")
	headers.Set("Content-Type", "application/octet-stream")
	response, err := c.read.request(ctx, http.MethodPut, c.stage, source, c.size, headers)
	if err != nil {
		return errors.Join(ErrDAVDelivery, err)
	}
	if err = davDeliveryAcknowledgement(response); err != nil || source.read.Load() != c.size {
		return errors.Join(ErrDAVDelivery, err)
	}
	return nil
}

func davDeliveryIdentity(response *HTTPSReadResponse) bool {
	encoding := response.Header.Values("Content-Encoding")
	return len(response.Header.Values("Content-Range")) == 0 && (len(encoding) == 0 || len(encoding) == 1 && encoding[0] == "identity")
}

// A single-file exclusive create/MOVE must return201,not204(replaced) or a
// multi-status/redirect. Untrusted response bodies remain bounded and inert.
func davDeliveryAcknowledgement(response *HTTPSReadResponse) error {
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated || !davDeliveryIdentity(response) || response.ContentLength > 32<<10 {
		return ErrDAVDelivery
	}
	n, err := io.CopyN(io.Discard, response.Body, (32<<10)+1)
	if n > 32<<10 || err != io.EOF {
		return ErrDAVDelivery
	}
	if err = response.Body.Close(); err != nil {
		return errors.Join(ErrDAVDelivery, err)
	}
	return nil
}

func davDeliveryStrongETag(values []string) string {
	if len(values) != 1 {
		return ""
	}
	tag := values[0]
	if len(tag) < 2 || len(tag) > 1024 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return ""
	}
	for _, b := range []byte(tag[1 : len(tag)-1]) {
		if b < 0x21 || b > 0x7e || b == '"' {
			return ""
		}
	}
	return tag
}

func (c *DAVDeliveryClient) verify(ctx context.Context, path string, stage bool) (string, error) {
	response, err := c.read.request(ctx, http.MethodGet, path, nil, 0, davDeliveryHeaders())
	if err != nil {
		return "", errors.Join(ErrDAVDelivery, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !davDeliveryIdentity(response) || response.ContentLength >= 0 && response.ContentLength != c.size {
		return "", ErrDAVDelivery
	}
	tag := davDeliveryStrongETag(response.Header.Values("Etag"))
	if stage && tag == "" {
		return "", ErrDAVDelivery
	}
	hash := NewDigest()
	buffer := make([]byte, 32<<10)
	defer Clear(buffer)
	for copied := int64(0); copied < c.size; {
		n, err := io.ReadFull(response.Body, buffer[:min(int64(len(buffer)), c.size-copied)])
		if err != nil {
			return "", errors.Join(ErrDAVDelivery, err)
		}
		hash.Write(buffer[:n])
		copied += int64(n)
	}
	var extra [1]byte
	if n, err := response.Body.Read(extra[:]); n != 0 || err != io.EOF || fmt.Sprintf("%x", hash.Sum(nil)) != c.digest {
		return "", ErrDAVDelivery
	}
	if err = response.Body.Close(); err != nil {
		return "", errors.Join(ErrDAVDelivery, err)
	}
	return tag, nil
}

func (c *DAVDeliveryClient) VerifyStage(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stageETag = ""
	if c.published {
		return ErrDAVDelivery
	}
	tag, err := c.verify(ctx, c.stage, true)
	if err == nil {
		c.stageETag = tag
	}
	return err
}

// Publish attempts one conditional MOVE of the exact verified stage revision.
// Destination always names the same approved TLS authority;no URI is supplied
// by a peer. A failed/absent acknowledgement remains ambiguous to the worker.
func (c *DAVDeliveryClient) Publish(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.published || c.stageETag == "" {
		return ErrDAVDelivery
	}
	c.published = true
	_, port, _ := net.SplitHostPort(c.read.dest.Address)
	destination := url.URL{Scheme: "https", Host: net.JoinHostPort(c.read.dest.ServerName, port), Path: c.final}
	headers := davDeliveryHeaders()
	headers.Set("Destination", destination.String())
	headers.Set("Overwrite", "F")
	headers.Set("If-Match", c.stageETag)
	response, err := c.read.request(ctx, "MOVE", c.stage, nil, 0, headers)
	if err != nil {
		return errors.Join(ErrDAVDelivery, err)
	}
	return davDeliveryAcknowledgement(response)
}

// VerifyFinal is read-only and may observe an original ambiguous publication.
// Matching bytes establish integrity at read time,not a business receipt/fsync.
func (c *DAVDeliveryClient) VerifyFinal(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.verify(ctx, c.final, false)
	return err
}
