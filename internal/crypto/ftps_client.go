package crypto

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/freightctl/internal/protectedfs"
)

var ErrFTPSClient = errors.New("FTPS receiver identity, credential or channel policy failed")

// FTPSDestination contains references and fingerprints, never a password value.
// This initial profile, like SSHDestination, accepts only numeric loopback peers.
type FTPSDestination struct {
	Address        string `json:"address"`
	ServerName     string `json:"server_name"`
	Mode           string `json:"mode"`
	User           string `json:"user"`
	CAFile         string `json:"ca_reference"`
	CASHA256       string `json:"ca_sha256"`
	PasswordFile   string `json:"password_reference"`
	PasswordSHA256 string `json:"password_sha256"`
}

func ftpsText(value string, max int) bool {
	if len(value) < 1 || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ValidateFTPSDestination checks the frozen reference shape without reading a
// credential or opening a socket. Work reopens and verifies the exact CA and
// password bytes; a syntactically valid reference does not grant authority.
func ValidateFTPSDestination(d FTPSDestination) error {
	host, port, err := net.SplitHostPort(d.Address)
	n, pErr := strconv.Atoi(port)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || pErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || (d.Mode != "explicit" && d.Mode != "implicit") || !ftpsText(d.ServerName, 253) || strings.ContainsAny(d.ServerName, "/\\ ") || (strings.Contains(d.ServerName, ":") && net.ParseIP(d.ServerName) == nil) || !ftpsText(d.User, 256) {
		return ErrFTPSClient
	}
	for _, ref := range []string{d.CAFile, d.PasswordFile} {
		if !filepath.IsAbs(ref) || filepath.Clean(ref) != ref || !ftpsText(ref, 1024) {
			return ErrFTPSClient
		}
	}
	for _, hash := range []string{d.CASHA256, d.PasswordSHA256} {
		if len(hash) != 64 {
			return ErrFTPSClient
		}
		for _, c := range hash {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return ErrFTPSClient
			}
		}
	}
	return nil
}

func ftpsTrust(d FTPSDestination) (*tls.Config, error) {
	if err := ValidateFTPSDestination(d); err != nil {
		return nil, err
	}
	st, err := os.Lstat(d.CAFile)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 128<<10 {
		return nil, ErrFTPSClient
	}
	f, err := os.Open(d.CAFile)
	if err != nil {
		return nil, ErrFTPSClient
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) || opened.Size() != st.Size() {
		return nil, ErrFTPSClient
	}
	if err = protectedfs.ValidatePublicFile(f); err != nil {
		return nil, ErrFTPSClient
	}
	b, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil || int64(len(b)) != st.Size() || Digest(b) != d.CASHA256 {
		return nil, ErrFTPSClient
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(b) {
		return nil, ErrFTPSClient
	}
	cfg := TLSConfig()
	cfg.MaxVersion = tls.VersionTLS13
	cfg.RootCAs = roots
	cfg.ServerName = d.ServerName
	return cfg, nil
}

// ReadFTPSPassword reopens the protected value and checks its approved identity.
// Call only after verified control TLS. The caller must close the owned buffer.
func ReadFTPSPassword(d FTPSDestination) (*Secret, error) {
	s, err := ReadSecret(d.PasswordFile, 1024)
	if err != nil {
		return nil, ErrFTPSClient
	}
	valid := utf8.Valid(s.Bytes)
	for rest := s.Bytes; valid && len(rest) > 0; {
		r, n := utf8.DecodeRune(rest)
		valid = !unicode.IsControl(r)
		rest = rest[n:]
	}
	if Digest(s.Bytes) != d.PasswordSHA256 || !valid {
		s.Close()
		return nil, ErrFTPSClient
	}
	return s, nil
}

// controlTicket holds one control session's ticket. Data sockets can read it but
// cannot replace it with a data ticket or borrow another client's session.
type controlTicket struct {
	sync.Mutex
	key   string
	state *tls.ClientSessionState
}

func (c *controlTicket) Get(key string) (*tls.ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()
	return c.state, c.state != nil && key == c.key
}
func (c *controlTicket) Put(key string, state *tls.ClientSessionState) {
	c.Lock()
	defer c.Unlock()
	c.key = key
	c.state = state
}

type dataTicket struct{ control *controlTicket }

func (c dataTicket) Get(key string) (*tls.ClientSessionState, bool) { return c.control.Get(key) }
func (c dataTicket) Put(string, *tls.ClientSessionState)            {}

// controlBudget limits TLS handshake, post-handshake tickets and replies before
// higher-level parsing. A hostile peer cannot stream unlimited ticket records.
type controlBudget struct {
	net.Conn
	remaining int64
}

func (c *controlBudget) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, ErrFTPSClient
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, e := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, e
}

// FTPSClientTransport owns control/data TCP sockets, TLS policy and cancellation.
// Protocol adapters cannot change trust, dial a supplied IP or relax resumption.
type FTPSClientTransport struct {
	mu          sync.Mutex
	raw         net.Conn
	control     io.ReadWriter
	data        *FTPSClientData
	opening     bool
	closed      bool
	secured     bool
	destination FTPSDestination
	config      *tls.Config
	ticket      *controlTicket
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	peer        string
	port        int
	leaf        string
	deadline    time.Time
}

func DialFTPSClient(ctx context.Context, d FTPSDestination) (*FTPSClientTransport, error) {
	cfg, err := ftpsTrust(d)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", d.Address)
	if err != nil {
		cancel()
		return nil, ErrFTPSClient
	}
	deadline, _ := ctx.Deadline()
	wrapped := &idleConn{Conn: raw, deadline: deadline, idle: 15 * time.Second}
	wrapped.active.Store(true)
	wrapped.touch()
	peer, port, _ := net.SplitHostPort(d.Address)
	n, _ := strconv.Atoi(port)
	t := &FTPSClientTransport{raw: wrapped, control: &controlBudget{Conn: wrapped, remaining: 512 << 10}, destination: d, config: cfg, ticket: &controlTicket{}, ctx: ctx, cancel: cancel, done: make(chan struct{}), peer: peer, port: n, deadline: deadline}
	go func() { defer close(t.done); <-ctx.Done(); t.closeSockets() }()
	if d.Mode == "implicit" {
		if err = t.SecureControl(); err != nil {
			t.Close()
			return nil, err
		}
	}
	return t, nil
}

func (t *FTPSClientTransport) SecureControl() error {
	t.mu.Lock()
	if t.closed || t.secured {
		t.mu.Unlock()
		return ErrFTPSClient
	}
	t.secured = true
	cfg := t.config.Clone()
	cfg.ClientSessionCache = t.ticket
	raw := t.control
	t.mu.Unlock()
	// controlBudget also implements net.Conn, and counts ciphertext below TLS.
	conn, ok := raw.(net.Conn)
	if !ok {
		return ErrFTPSClient
	}
	client := tls.Client(conn, cfg)
	if err := client.HandshakeContext(t.ctx); err != nil {
		return ErrFTPSClient
	}
	s := client.ConnectionState()
	if s.Version != tls.VersionTLS13 || s.DidResume || len(s.PeerCertificates) == 0 || len(s.PeerCertificates) > 8 {
		return ErrFTPSClient
	}
	var bytes int
	for _, cert := range s.PeerCertificates {
		bytes += len(cert.Raw)
	}
	if bytes > 128<<10 {
		return ErrFTPSClient
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return ErrFTPSClient
	}
	t.control = client
	t.leaf = Digest(s.PeerCertificates[0].Raw)
	return nil
}
func (t *FTPSClientTransport) Read(p []byte) (int, error) {
	t.mu.Lock()
	c := t.control
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, ErrFTPSClient
	}
	return c.Read(p)
}
func (t *FTPSClientTransport) Write(p []byte) (int, error) {
	t.mu.Lock()
	c := t.control
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return 0, ErrFTPSClient
	}
	return c.Write(p)
}
func (t *FTPSClientTransport) closeSockets() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	raw, data := t.raw, t.data
	t.mu.Unlock()
	_ = raw.Close()
	if data != nil {
		_ = data.Abort()
	}
}
func (t *FTPSClientTransport) Close() error { t.cancel(); t.closeSockets(); <-t.done; return nil }

// OpenData connects only to the approved control peer's unprivileged port. TLS
// starts after the protocol's preliminary transfer reply, as some peers require.
func (t *FTPSClientTransport) OpenData(port int) (*FTPSClientData, error) {
	t.mu.Lock()
	if t.closed || !t.secured || t.leaf == "" || t.data != nil || t.opening || port < 1024 || port > 65535 || port == t.port {
		t.mu.Unlock()
		return nil, ErrFTPSClient
	}
	t.opening = true
	leaf := t.leaf
	cfg := t.config.Clone()
	cfg.ClientSessionCache = dataTicket{t.ticket}
	cfg.VerifyConnection = func(s tls.ConnectionState) error {
		if s.Version != tls.VersionTLS13 || !s.DidResume || len(s.PeerCertificates) == 0 || Digest(s.PeerCertificates[0].Raw) != leaf {
			return ErrFTPSClient
		}
		return nil
	}
	t.mu.Unlock()
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.ctx, "tcp", net.JoinHostPort(t.peer, strconv.Itoa(port)))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.opening = false
	if err != nil {
		return nil, ErrFTPSClient
	}
	if t.closed {
		raw.Close()
		return nil, ErrFTPSClient
	}
	wrapped := &idleConn{Conn: raw, deadline: t.deadline, idle: 15 * time.Second}
	wrapped.active.Store(true)
	wrapped.touch()
	d := &FTPSClientData{raw: wrapped, client: tls.Client(ftpsDataConn{wrapped}, cfg), parent: t}
	t.data = d
	return d, nil
}

type FTPSClientData struct {
	raw      net.Conn
	client   *tls.Conn
	parent   *FTPSClientTransport
	once     sync.Once
	closeErr error
}

// Go TLS accepts bare TCP EOF at a record boundary for web compatibility.
// FTPS requires the encrypted close_notify message: translate the underlying
// socket's EOF before TLS can normalize it. A genuine TLS alert still produces
// io.EOF above TLS, while an abrupt transport close remains an error.
type ftpsDataConn struct{ net.Conn }

func (c ftpsDataConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		err = ErrFTPSClient
	}
	return n, err
}

func (d *FTPSClientData) Handshake() error {
	if err := d.client.HandshakeContext(d.parent.ctx); err != nil {
		return ErrFTPSClient
	}
	return nil
}
func (d *FTPSClientData) Read(p []byte) (int, error)  { return d.client.Read(p) }
func (d *FTPSClientData) Write(p []byte) (int, error) { return d.client.Write(p) }
func (d *FTPSClientData) finish(clean bool) error {
	d.once.Do(func() {
		if clean {
			d.closeErr = d.client.CloseWrite()
			if d.closeErr == nil {
				var tail [1]byte
				if n, err := d.client.Read(tail[:]); n != 0 || err != io.EOF {
					d.closeErr = ErrFTPSClient
				}
			}
			_ = d.raw.Close()
		} else {
			d.closeErr = d.raw.Close()
		}
		d.parent.mu.Lock()
		if d.parent.data == d {
			d.parent.data = nil
		}
		d.parent.mu.Unlock()
	})
	return d.closeErr
}
func (d *FTPSClientData) Close() error { return d.finish(true) }

// Abort deliberately omits TLS close_notify after a failed/incomplete stream.
func (d *FTPSClientData) Abort() error { _ = d.raw.Close(); return d.finish(false) }
