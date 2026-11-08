package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/vpath"
)

var ErrHTTPSRead = errors.New("HTTPS source identity,credential or read policy failed")

// HTTPSReadDestination pins a numeric endpoint and its TLS name independently.
// Only protected references and approved fingerprints enter durable metadata.
// DNS resolution,proxies,redirects,ambient roots and mutation methods are absent.
type HTTPSReadDestination struct {
	Address        string `json:"address"`
	ServerName     string `json:"server_name"`
	CAFile         string `json:"ca_reference"`
	CASHA256       string `json:"ca_sha256"`
	TokenFile      string `json:"token_reference,omitempty"`
	TokenSHA256    string `json:"token_sha256,omitempty"`
	Authentication string `json:"authentication,omitempty"`
	User           string `json:"user,omitempty"`
	PasswordFile   string `json:"password_reference,omitempty"`
	PasswordSHA256 string `json:"password_sha256,omitempty"`
}

func httpsReadDigest(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func httpsReadServerName(name string) bool {
	if ip := net.ParseIP(name); ip != nil {
		return ip.String() == name
	}
	if len(name) < 1 || len(name) > 253 {
		return false
	}
	for _, part := range strings.Split(name, ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' || strings.Trim(part, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

func ValidateHTTPSReadDestination(d HTTPSReadDestination) error {
	host, port, err := net.SplitHostPort(d.Address)
	n, portErr := strconv.Atoi(port)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || ip.String() != host || ip.IsUnspecified() || ip.IsMulticast() || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || !httpsReadServerName(d.ServerName) {
		return ErrHTTPSRead
	}
	credentialRef, credentialHash := d.TokenFile, d.TokenSHA256
	switch d.Authentication {
	case "":
		if d.User != "" || d.PasswordFile != "" || d.PasswordSHA256 != "" {
			return ErrHTTPSRead
		}
	case "basic":
		if d.TokenFile != "" || d.TokenSHA256 != "" || !ftpsText(d.User, 256) || strings.Contains(d.User, ":") {
			return ErrHTTPSRead
		}
		credentialRef, credentialHash = d.PasswordFile, d.PasswordSHA256
	default:
		return ErrHTTPSRead
	}
	for _, ref := range []string{d.CAFile, credentialRef} {
		if !filepath.IsAbs(ref) || filepath.Clean(ref) != ref || !ftpsText(ref, 1024) {
			return ErrHTTPSRead
		}
	}
	if !httpsReadDigest(d.CASHA256) || !httpsReadDigest(credentialHash) {
		return ErrHTTPSRead
	}
	return nil
}

// Basic is an explicit UTF8 credential profile,not a challenge-selected fallback.
// Both forms are disclosed only over the exact pinned TLS endpoint. Standard
// HTTP libraries retain transient header strings;owned secret buffers are cleared.
func httpsReadAuthorization(d HTTPSReadDestination) (string, *Secret, error) {
	if d.Authentication == "basic" {
		password, err := ReadSecret(d.PasswordFile, 1024)
		if err != nil {
			return "", nil, ErrHTTPSRead
		}
		valid := Digest(password.Bytes) == d.PasswordSHA256 && utf8.Valid(password.Bytes)
		for rest := password.Bytes; valid && len(rest) > 0; {
			r, n := utf8.DecodeRune(rest)
			valid = !unicode.IsControl(r)
			rest = rest[n:]
		}
		if !valid {
			password.Close()
			return "", nil, ErrHTTPSRead
		}
		combined := make([]byte, len(d.User)+1+len(password.Bytes))
		copy(combined, d.User)
		combined[len(d.User)] = ':'
		copy(combined[len(d.User)+1:], password.Bytes)
		encoded := base64.StdEncoding.EncodeToString(combined)
		Clear(combined)
		return "Basic " + encoded, password, nil
	}
	token, err := ReadSecret(d.TokenFile, 4096)
	if err != nil {
		return "", nil, ErrHTTPSRead
	}
	value := string(token.Bytes)
	plain := strings.TrimRight(value, "=")
	if len(plain) < 1 || strings.Trim(plain, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/") != "" || Digest(token.Bytes) != d.TokenSHA256 {
		token.Close()
		return "", nil, ErrHTTPSRead
	}
	return "Bearer " + value, token, nil
}

func httpsReadTrust(d HTTPSReadDestination) (*tls.Config, error) {
	st, err := os.Lstat(d.CAFile)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 128<<10 {
		return nil, ErrHTTPSRead
	}
	f, err := os.Open(d.CAFile)
	if err != nil {
		return nil, ErrHTTPSRead
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || opened.Size() != st.Size() || protectedfs.ValidatePublicFile(f) != nil {
		return nil, ErrHTTPSRead
	}
	data, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil || int64(len(data)) != st.Size() || Digest(data) != d.CASHA256 {
		return nil, ErrHTTPSRead
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, ErrHTTPSRead
	}
	cfg := TLSConfig()
	cfg.MaxVersion, cfg.RootCAs, cfg.ServerName = tls.VersionTLS13, roots, d.ServerName
	return cfg, nil
}

// Each socket operation has an idle deadline,not an aggregate file deadline.
// Large streams can continue while making progress and retaining live authority.
type httpsReadConn struct{ net.Conn }

func (c httpsReadConn) Read(data []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Read(data)
}
func (c httpsReadConn) Write(data []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}

type HTTPSReadClient struct {
	ctx       context.Context
	cancel    context.CancelFunc
	transport *http.Transport
	client    *http.Client
	dest      HTTPSReadDestination
	check     func() error
}

func NewHTTPSReadClient(ctx context.Context, d HTTPSReadDestination, check func() error) (*HTTPSReadClient, error) {
	if ValidateHTTPSReadDestination(d) != nil || check == nil {
		return nil, ErrHTTPSRead
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	trust, err := httpsReadTrust(d)
	if err != nil {
		return nil, err
	}
	root, cancel := context.WithCancel(ctx)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: trust, DisableCompression: true,
		MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 10 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 64 << 10}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != d.Address {
			return nil, ErrHTTPSRead
		}
		socket, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
		if err != nil {
			return nil, ErrHTTPSRead
		}
		return httpsReadConn{socket}, nil
	}
	return &HTTPSReadClient{ctx: root, cancel: cancel, transport: transport, dest: d, check: check,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *HTTPSReadClient) Close() error {
	c.cancel()
	c.transport.CloseIdleConnections()
	return nil
}

// No original HTTP Request escapes:it contains the transient authentication header.
type HTTPSReadResponse struct {
	StatusCode    int
	ContentLength int64
	Header        http.Header
	Body          io.ReadCloser
}

type httpsReadBody struct {
	body   io.ReadCloser
	ctx    context.Context
	check  func() error
	cancel context.CancelFunc
	stop   func() bool
}

func (b *httpsReadBody) Read(data []byte) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if err := b.check(); err != nil {
		b.Close()
		return 0, err
	}
	n, err := b.body.Read(data)
	if e := b.check(); e != nil {
		b.Close()
		return 0, e
	}
	if e := b.ctx.Err(); e != nil {
		return 0, e
	}
	return n, err
}
func (b *httpsReadBody) Close() error {
	b.stop()
	b.cancel()
	return b.body.Close()
}

// Get has no method,origin,query,redirect,proxy or credential override. Protocol
// code can only read a canonical path at the exact approved TLS endpoint.
func (c *HTTPSReadClient) Get(ctx context.Context, target string) (*HTTPSReadResponse, error) {
	return c.request(ctx, http.MethodGet, target, nil, 0, nil)
}

// Kept private inside the cryptographic transport boundary. The exported source
// client still exposes only GET;delivery owns a separate narrowly bound type.
func (c *HTTPSReadClient) request(ctx context.Context, method, target string, body io.Reader, size int64, headers http.Header) (*HTTPSReadResponse, error) {
	canonical, err := vpath.Canonical(target)
	if err != nil || canonical != target || vpath.ControlPath(target) {
		return nil, ErrHTTPSRead
	}
	op, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	failed := true
	defer func() {
		if failed {
			stop()
			cancel()
		}
	}()
	if c.ctx.Err() != nil || op.Err() != nil {
		return nil, context.Canceled
	}
	if err = c.check(); err != nil {
		return nil, err
	}
	authorization, credential, err := httpsReadAuthorization(c.dest)
	if err != nil {
		return nil, ErrHTTPSRead
	}
	defer credential.Close()
	u := url.URL{Scheme: "https", Host: c.dest.Address, Path: target}
	request, err := http.NewRequestWithContext(op, method, u.String(), body)
	if err != nil {
		return nil, ErrHTTPSRead
	}
	_, port, _ := net.SplitHostPort(c.dest.Address)
	request.Host = net.JoinHostPort(c.dest.ServerName, port)
	if body != nil {
		request.ContentLength = size
		if size == 0 {
			request.Body = http.NoBody
		}
	}
	// An effect is never made replayable by a rewind function or retry key.
	request.GetBody = nil
	for name, values := range headers {
		request.Header[name] = append([]string(nil), values...)
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Accept-Encoding", "identity")
	defer request.Header.Del("Authorization")
	response, err := c.client.Do(request)
	if err != nil {
		if op.Err() != nil {
			return nil, op.Err()
		}
		return nil, ErrHTTPSRead
	}
	if err = c.check(); err != nil {
		response.Body.Close()
		return nil, err
	}
	if response.Uncompressed || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		response.Body.Close()
		return nil, ErrHTTPSRead
	}
	failed = false
	return &HTTPSReadResponse{StatusCode: response.StatusCode, ContentLength: response.ContentLength,
		Header: response.Header.Clone(), Body: &httpsReadBody{body: response.Body, ctx: op, check: c.check, cancel: cancel, stop: stop}}, nil
}
