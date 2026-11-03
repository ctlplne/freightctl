// Package ftpsd maps authenticated FTP-over-TLS sessions to shared custody.
// The pinned protocol engine owns FTP framing and internally uses Go TLS;
// identity loading and channel-binding policy remain in internal/crypto.
package ftpsd

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	ftp "github.com/fclairamb/ftpserverlib"
)

type Options struct {
	Identity                   *secure.FTPSIdentity
	Implicit, EnableActive     bool
	MaxConnections, MaxWriters int
	ListLimit                  int
	SessionLimit, IdleLimit    time.Duration
}

type Server struct {
	custody *custody.Service
	options Options
	writers chan struct{}
}

var errSession = errors.New("FTPS session refused")

func New(service *custody.Service, options Options) (*Server, error) {
	if service == nil || service.DB == nil || service.Disk == nil || service.MaxFile < 1 || service.MaxStored < service.MaxFile || service.NamespaceMaxEntries < 1 || options.Identity == nil {
		return nil, errSession
	}
	if options.MaxConnections < 1 || options.MaxConnections > 32 || options.MaxWriters < 1 || options.MaxWriters > 4 || options.ListLimit < 1 || options.ListLimit > 10000 {
		return nil, errSession
	}
	if options.SessionLimit < time.Second || options.SessionLimit > time.Hour || options.IdleLimit < time.Second || options.IdleLimit > options.SessionLimit {
		return nil, errSession
	}
	return &Server{custody: service, options: options, writers: make(chan struct{}, options.MaxWriters)}, nil
}

// Serve owns the supplied loopback listener and waits for its task-owned
// sessions to cancel and close their handles before returning.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || addr == nil || !addr.IP.IsLoopback() || addr.Port < 1 {
		return errSession
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	slots := make(chan struct{}, s.options.MaxConnections)
	var sessions sync.WaitGroup
	defer sessions.Wait()
	defer cancel()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errSession
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			defer func() { <-slots }()
			s.session(ctx, conn)
		}()
	}
}

func (s *Server) session(parent context.Context, raw net.Conn) {
	defer raw.Close()
	ctx, cancel := context.WithTimeout(parent, s.options.SessionLimit)
	defer cancel()
	binding, err := s.options.Identity.BindFTPSControl(raw.LocalAddr())
	if err != nil {
		return
	}
	defer binding.Close()
	end, _ := ctx.Deadline()
	conn := net.Conn(&deadlineConn{Conn: raw, end: end, idle: s.options.IdleLimit})
	if s.options.Implicit {
		conn = binding.FTPSImplicitServer(conn)
	}
	l := &singleListener{conn: conn, raw: raw, done: make(chan struct{})}
	d := &sessionDriver{server: s, ctx: ctx, cancel: cancel, binding: binding, listener: l, end: end,
		passive: make(map[*passiveListener]struct{}), data: make(map[*deadlineConn]struct{}), departed: make(chan struct{})}
	defer d.stop()
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			d.stop()
		case <-watchDone:
		}
	}()
	engine := ftp.NewFtpServer(d) // Upstream's default logger discards all output.
	_ = engine.ListenAndServe()
	_ = engine.Stop()
	d.stop()
	if l.wasAccepted() {
		<-d.departed
	}
}

type sessionDriver struct {
	server     *Server
	ctx        context.Context
	cancel     context.CancelFunc
	binding    *secure.FTPSChannelBinding
	listener   *singleListener
	end        time.Time
	mu         sync.Mutex
	closed     bool
	fs         *filesystem
	passive    map[*passiveListener]struct{}
	data       map[*deadlineConn]struct{}
	pbsz, prot bool
	stopOnce   sync.Once
	departed   chan struct{}
}

func (d *sessionDriver) GetSettings() (*ftp.Settings, error) {
	local := d.listener.Addr().(*net.TCPAddr)
	mode := ftp.MandatoryEncryption
	if d.server.options.Implicit {
		mode = ftp.ImplicitEncryption
	}
	public := ""
	if local.IP.To4() != nil {
		public = local.IP.String()
	}
	return &ftp.Settings{Listener: d.listener, PublicHost: public, PassiveTransferListenIP: local.IP.String(), Banner: "freightctl custody",
		TLSRequired: mode, IdleTimeout: int(d.server.options.IdleLimit / time.Second), ConnectionTimeout: 5,
		DisableSite: true, DisableSTAT: true, DisableMFMT: true, DisableLISTArgs: true, DisableActiveMode: !d.server.options.EnableActive,
		DefaultTransferType: ftp.TransferTypeBinary, ActiveTransferPortNon20: true,
		ActiveTransferLocalIPResolver: func(ftp.ClientContext) net.IP { return local.IP }}, nil
}

func (d *sessionDriver) GetTLSConfig() (*secure.TLSConfiguration, error) {
	return d.binding.TLSConfig(), nil
}
func (d *sessionDriver) ClientConnected(cc ftp.ClientContext) (string, error) {
	if d.ctx.Err() != nil {
		return "", errSession
	}
	return "freightctl: encrypted commands and session-bound encrypted data required", nil
}
func (d *sessionDriver) ClientDisconnected(ftp.ClientContext) {
	d.stop()
	close(d.departed)
}
func (d *sessionDriver) PreAuthUser(cc ftp.ClientContext, user string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.fs != nil || !cc.HasTLSForControl() || len(user) != 73 {
		return errSession
	}
	return nil
}
func (d *sessionDriver) AuthUser(cc ftp.ClientContext, user, pass string) (ftp.ClientDriver, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.fs != nil || !cc.HasTLSForControl() || len(user) != 73 || user[36] != '/' || !store.ValidID(user[:36]) || !store.ValidID(user[37:]) || len(pass) != 64 {
		return nil, errSession
	}
	for _, c := range pass {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errSession
		}
	}
	secret := secure.ProtectBytes([]byte(pass))
	defer secret.Close()
	scope := store.Scope{Tenant: user[:36], Partner: user[37:], TokenHash: secure.Digest(secret.Bytes), SessionID: secure.NewID()}
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel()
	t, err := d.server.custody.DB.Begin(ctx, scope)
	if err != nil {
		return nil, errSession
	}
	defer t.Tx.Rollback(ctx)
	protocol := "ftps-explicit"
	if d.server.options.Implicit {
		protocol = "ftps-implicit"
	}
	_, err = t.Append(ctx, "ProtocolSessionStarted", scope.SessionID, map[string]any{"protocol": protocol, "authority_revision": t.AuthorityRevision, "tls_profile": "tls13-resumed-data-v1"})
	if err == nil {
		err = t.Reauthorize(ctx)
	}
	if err == nil {
		err = t.Tx.Commit(ctx)
	}
	if err != nil || d.binding.AllowData() != nil {
		return nil, errSession
	}
	scope.AuthorityRevision = t.AuthorityRevision
	d.fs = &filesystem{driver: d, scope: scope, open: make(map[*transfer]struct{})}
	return d.fs, nil
}

func (d *sessionDriver) stop() {
	d.stopOnce.Do(func() {
		d.cancel()
		d.binding.Close()
		_ = d.listener.Close()
		d.mu.Lock()
		d.closed = true
		var listeners []*passiveListener
		var data []*deadlineConn
		for l := range d.passive {
			listeners = append(listeners, l)
		}
		for c := range d.data {
			data = append(data, c)
		}
		fs := d.fs
		d.mu.Unlock()
		for _, l := range listeners {
			_ = l.Close()
		}
		for _, c := range data {
			_ = c.Close()
		}
		if fs != nil {
			fs.abort()
		}
	})
}

func (d *sessionDriver) WrapPassiveListener(l net.Listener) (net.Listener, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.passive) >= 2 || !l.Addr().(*net.TCPAddr).IP.IsLoopback() {
		_ = l.Close()
		return nil, errSession
	}
	p := &passiveListener{Listener: l, driver: d}
	d.passive[p] = struct{}{}
	return p, nil
}

type passiveListener struct {
	net.Listener
	driver *sessionDriver
	once   sync.Once
}

func (p *passiveListener) Accept() (net.Conn, error) {
	c, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return p.driver.WrapActiveConnection(c)
}

// Both data directions use the same bounded socket owner; the method name
// also satisfies the protocol engine's active-connection wrapper extension.
func (d *sessionDriver) WrapActiveConnection(c net.Conn) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.data) >= 2 {
		_ = c.Close()
		return nil, errSession
	}
	w := &deadlineConn{Conn: c, end: d.end, idle: d.server.options.IdleLimit}
	w.release = func() { d.mu.Lock(); delete(d.data, w); d.mu.Unlock() }
	d.data[w] = struct{}{}
	return w, nil
}
func (p *passiveListener) Close() error {
	err := p.Listener.Close()
	p.once.Do(func() { p.driver.mu.Lock(); delete(p.driver.passive, p); p.driver.mu.Unlock() })
	return err
}

type singleListener struct {
	conn, raw        net.Conn
	mu               sync.Mutex
	accepted, closed bool
	done             chan struct{}
}

func (l *singleListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Addr() net.Addr    { return l.conn.LocalAddr() }
func (l *singleListener) wasAccepted() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.accepted }
func (l *singleListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	return l.raw.Close()
}

type deadlineConn struct {
	net.Conn
	end     time.Time
	idle    time.Duration
	once    sync.Once
	release func()
}

func (c *deadlineConn) bound(t time.Time) time.Time {
	if t.IsZero() || t.After(c.end) {
		return c.end
	}
	return t
}
func (c *deadlineConn) SetDeadline(t time.Time) error     { return c.Conn.SetDeadline(c.bound(t)) }
func (c *deadlineConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(c.bound(t)) }
func (c *deadlineConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.bound(t))
}
func (c *deadlineConn) Read(p []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Read(p)
	// TLS close_notify is processed inside tls.Conn before a raw socket EOF.
	// An unnotified EOF must remain a transfer error; Go TLS otherwise accepts
	// a record-boundary TCP EOF for compatibility, which can seal a short file.
	if err == io.EOF {
		err = errors.New("FTPS transport closed without TLS completion")
	}
	return n, err
}
func (c *deadlineConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}
func (c *deadlineConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return err
}
