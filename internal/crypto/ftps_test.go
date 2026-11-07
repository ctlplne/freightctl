package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type ftpsTLSResult struct {
	state tls.ConnectionState
	err   error
}

func ftpsIdentityFixture(t *testing.T) (*FTPSIdentity, *tls.Config, string, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	identity, err := LoadFTPSIdentity(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("fixture certificate was not parsed")
	}
	client := TLSConfig()
	client.RootCAs = roots
	client.ServerName = "localhost"
	return identity, client, cert, key
}

func ftpsTestListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// Both endpoints use real loopback TCP and certificate-verified TLS. The byte
// read also processes TLS1.3's post-handshake session ticket at the client.
func ftpsTLSExchange(t *testing.T, listener net.Listener, server, client *tls.Config) (tls.ConnectionState, error, error) {
	t.Helper()
	done := make(chan ftpsTLSResult, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- ftpsTLSResult{err: err}
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		conn := tls.Server(c, server)
		err = conn.Handshake()
		if err == nil {
			_, err = conn.Write([]byte{42})
		}
		done <- ftpsTLSResult{state: conn.ConnectionState(), err: err}
	}()
	conn, clientErr := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), client)
	if clientErr == nil {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var b [1]byte
		_, clientErr = io.ReadFull(conn, b[:])
		if clientErr == nil && b[0] != 42 {
			clientErr = errors.New("incorrect test payload")
		}
		_ = conn.Close()
	}
	select {
	case result := <-done:
		return result.state, result.err, clientErr
	case <-time.After(4 * time.Second):
		t.Fatal("TLS fixture exceeded its deadline")
		return tls.ConnectionState{}, nil, nil
	}
}

func TestFTPSDataTLSResumesOnlyItsAuthenticatedControlSession(t *testing.T) {
	identity, client, _, _ := ftpsIdentityFixture(t)
	control, data := ftpsTestListener(t), ftpsTestListener(t)
	binding, err := identity.BindFTPSControl(control.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	state, serverErr, clientErr := ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil || state.DidResume || state.Version != tls.VersionTLS13 {
		t.Fatalf("fresh verified control: resume=%v version=%d server=%v client=%v", state.DidResume, state.Version, serverErr, clientErr)
	}
	if err := binding.AllowData(); err != nil {
		t.Fatal(err)
	}
	state, serverErr, clientErr = ftpsTLSExchange(t, data, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil || !state.DidResume || state.Version != tls.VersionTLS13 {
		t.Fatalf("bound data: resume=%v version=%d server=%v client=%v", state.DidResume, state.Version, serverErr, clientErr)
	}
	// A different process behind the same loopback address has no ticket.
	stranger := client.Clone()
	stranger.ClientSessionCache = nil
	_, serverErr, clientErr = ftpsTLSExchange(t, data, binding.TLSConfig(), stranger)
	if serverErr == nil || clientErr == nil {
		t.Fatal("same-IP data client without the control ticket was accepted")
	}
	// Another control session has a different ticket key, even with the same
	// server certificate, hostname and network address.
	otherControl := ftpsTestListener(t)
	other, err := identity.BindFTPSControl(otherControl.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.AllowData(); err != nil {
		t.Fatal(err)
	}
	_, serverErr, clientErr = ftpsTLSExchange(t, data, other.TLSConfig(), client)
	if serverErr == nil || clientErr == nil {
		t.Fatal("ticket crossed control-session boundary")
	}
}

func TestFTPSDataTLSRequiresApplicationAuthenticationAndLiveBinding(t *testing.T) {
	identity, client, _, _ := ftpsIdentityFixture(t)
	control, data := ftpsTestListener(t), ftpsTestListener(t)
	binding, err := identity.BindFTPSControl(control.Addr())
	if err != nil {
		t.Fatal(err)
	}
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	_, serverErr, clientErr := ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil {
		t.Fatal("control handshake failed", serverErr, clientErr)
	}
	_, serverErr, clientErr = ftpsTLSExchange(t, data, binding.TLSConfig(), client)
	if serverErr == nil || clientErr == nil {
		t.Fatal("TLS ticket granted data access before application authentication")
	}
	if err := binding.AllowData(); err != nil {
		t.Fatal(err)
	}
	if err := binding.AllowData(); err == nil {
		t.Fatal("binding accepted a second authentication")
	}
	// The failed unauthenticated handshake may evict a client ticket. Obtain
	// another real control ticket before checking shutdown with a live cache.
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	_, serverErr, clientErr = ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil {
		t.Fatal("fresh control ticket failed", serverErr, clientErr)
	}
	binding.Close()
	if err := binding.AllowData(); err == nil {
		t.Fatal("closed binding was reopened")
	}
	_, serverErr, clientErr = ftpsTLSExchange(t, data, binding.TLSConfig(), client)
	if serverErr == nil || clientErr == nil {
		t.Fatal("closed binding accepted a data handshake")
	}
	_, serverErr, clientErr = ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr == nil || clientErr == nil {
		t.Fatal("closed binding accepted a control handshake")
	}
}

func TestFTPSControlTLSRejectsReusingADataTicketAsANewControl(t *testing.T) {
	identity, client, _, _ := ftpsIdentityFixture(t)
	control, data := ftpsTestListener(t), ftpsTestListener(t)
	binding, err := identity.BindFTPSControl(control.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	_, serverErr, clientErr := ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil {
		t.Fatal("control handshake failed", serverErr, clientErr)
	}
	if err := binding.AllowData(); err != nil {
		t.Fatal(err)
	}
	state, serverErr, clientErr := ftpsTLSExchange(t, data, binding.TLSConfig(), client)
	if serverErr != nil || clientErr != nil || !state.DidResume {
		t.Fatal("data resumption failed", serverErr, clientErr)
	}
	_, serverErr, clientErr = ftpsTLSExchange(t, control, binding.TLSConfig(), client)
	if serverErr == nil || clientErr == nil {
		t.Fatal("a resumed session became a new control connection")
	}
}

func TestFTPSTLSRequiresTrustedServerAndTLS13(t *testing.T) {
	identity, client, _, _ := ftpsIdentityFixture(t)
	control := ftpsTestListener(t)
	binding, err := identity.BindFTPSControl(control.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	for _, mode := range []string{"untrusted-certificate", "tls12", "wrong-hostname"} {
		t.Run(mode, func(t *testing.T) {
			bad := client.Clone()
			switch mode {
			case "untrusted-certificate":
				bad.RootCAs = x509.NewCertPool()
			case "tls12":
				bad.MinVersion, bad.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			case "wrong-hostname":
				bad.ServerName = "untrusted.invalid"
			}
			_, serverErr, clientErr := ftpsTLSExchange(t, control, binding.TLSConfig(), bad)
			if serverErr == nil || clientErr == nil {
				t.Fatal("invalid TLS peer was accepted")
			}
		})
	}
}

func TestFTPSIdentityRejectsUnsafeOrMismatchedFiles(t *testing.T) {
	identity, _, cert, key := ftpsIdentityFixture(t)
	for _, addr := range []net.Addr{nil, (*net.TCPAddr)(nil), &net.TCPAddr{Port: 1}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}} {
		if _, err := identity.BindFTPSControl(addr); err == nil {
			t.Fatal("invalid control address accepted")
		}
	}
	setReferenceAccessForTest(t, key, 0644)
	if _, err := LoadFTPSIdentity(cert, key); err == nil {
		t.Fatal("world-readable private key accepted")
	}
	setReferenceAccessForTest(t, key, 0600)
	setReferenceAccessForTest(t, cert, 0666)
	if _, err := LoadFTPSIdentity(cert, key); err == nil {
		t.Fatal("certificate writable by another user accepted")
	}
	setReferenceAccessForTest(t, cert, 0644)
	if _, err := LoadFTPSIdentity(cert, key); err != nil {
		t.Fatal("public read-only certificate refused", err)
	}
	link := filepath.Join(t.TempDir(), "certificate-link.pem")
	if err := os.Symlink(cert, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFTPSIdentity(link, key); err == nil {
		t.Fatal("certificate symlink accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFTPSIdentity(cert, link); err == nil {
		t.Fatal("private key symlink accepted")
	}
	_, _, otherCert, otherKey := ftpsIdentityFixture(t)
	if _, err := LoadFTPSIdentity(otherCert, key); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if _, err := LoadFTPSIdentity(cert, otherKey); err == nil {
		t.Fatal("mismatched certificate accepted")
	}
	if err := os.WriteFile(otherCert, make([]byte, (128<<10)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFTPSIdentity(otherCert, otherKey); err == nil {
		t.Fatal("oversized certificate accepted")
	}
}
