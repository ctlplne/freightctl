package crypto

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
)

// TLSConfiguration keeps protocol adapters inside the cryptographic boundary.
// Adapters consume the configuration; they must not relax or mutate its policy.
type TLSConfiguration = tls.Config

// FTPSIdentity owns the parsed server key inside the cryptographic boundary.
// TLS makes its own key objects; clearing the PEM buffer cannot erase those
// library-owned objects. A server retains this identity for its bounded lifetime.
type FTPSIdentity struct{ certificate tls.Certificate }

var errFTPSIdentity = errors.New("invalid FTPS certificate or protected key reference")
var errFTPSBinding = errors.New("FTPS data connection is not bound to an authenticated control session")

// LoadFTPSIdentity accepts a bounded regular certificate file and a protected
// key reference. Neither pathname nor library parsing error reaches the peer.
func LoadFTPSIdentity(certFile, keyFile string) (*FTPSIdentity, error) {
	info, err := os.Lstat(certFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 128<<10 {
		return nil, errFTPSIdentity
	}
	f, err := os.Open(certFile)
	if err != nil {
		return nil, errFTPSIdentity
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() != info.Size() {
		return nil, errFTPSIdentity
	}
	cert, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil || int64(len(cert)) != info.Size() {
		return nil, errFTPSIdentity
	}
	key, err := ReadSecret(keyFile, 128<<10)
	if err != nil {
		return nil, errFTPSIdentity
	}
	defer key.Close()
	pair, err := tls.X509KeyPair(cert, key.Bytes)
	if err != nil || len(pair.Certificate) > 8 {
		return nil, errFTPSIdentity
	}
	return &FTPSIdentity{certificate: pair}, nil
}

// FTPSChannelBinding gives exactly one control connection its own unpredictable
// ticket key. A data connection must resume a TLS1.3 session using that key.
// Clients sharing an IP address therefore cannot exchange data-channel tickets.
// This proves TLS channel continuity, not account authority or file acceptance;
// the adapter must still reauthorize each operation through the custody service.
type FTPSChannelBinding struct {
	config *tls.Config
	phase  atomic.Uint32 // 0: control only, 1: authenticated, 2: permanently closed
}

// BindFTPSControl must be called once for each accepted control connection,
// before its explicit AUTH TLS or implicit TLS handshake. The same immutable
// configuration is used for that control connection and its data connections.
func (i *FTPSIdentity) BindFTPSControl(local net.Addr) (*FTPSChannelBinding, error) {
	tcp, ok := local.(*net.TCPAddr)
	if i == nil || len(i.certificate.Certificate) == 0 || !ok || tcp == nil || tcp.IP == nil || tcp.Port < 1 || tcp.Port > 65535 {
		return nil, errFTPSBinding
	}
	controlAddress := tcp.String()
	key := ProtectBytes(make([]byte, 32))
	defer key.Close()
	if _, err := io.ReadFull(rand.Reader, key.Bytes); err != nil {
		return nil, errFTPSBinding
	}
	var tickets [1][32]byte
	copy(tickets[0][:], key.Bytes)
	defer Clear(tickets[0][:])
	b := &FTPSChannelBinding{}
	control := TLSConfig()
	control.Certificates = []tls.Certificate{i.certificate}
	control.SetSessionTicketKeys(tickets[:])
	control.VerifyConnection = func(state tls.ConnectionState) error {
		if b.phase.Load() == 2 || state.Version != tls.VersionTLS13 || state.DidResume {
			return errFTPSBinding
		}
		return nil
	}
	data := TLSConfig()
	data.Certificates = []tls.Certificate{i.certificate}
	data.SetSessionTicketKeys(tickets[:])
	data.VerifyConnection = func(state tls.ConnectionState) error {
		if b.phase.Load() != 1 || state.Version != tls.VersionTLS13 || !state.DidResume {
			return errFTPSBinding
		}
		return nil
	}
	b.config = TLSConfig()
	b.config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello == nil || hello.Conn == nil || b.phase.Load() == 2 {
			return nil, errFTPSBinding
		}
		if hello.Conn.LocalAddr().String() == controlAddress {
			return control, nil
		}
		return data, nil
	}
	return b, nil
}

func (b *FTPSChannelBinding) TLSConfig() *TLSConfiguration { return b.config }

// AllowData follows successful application authentication and its audit commit.
// Closing a binding is irreversible, even if authentication races with shutdown.
func (b *FTPSChannelBinding) AllowData() error {
	if !b.phase.CompareAndSwap(0, 1) {
		return errFTPSBinding
	}
	return nil
}

// Close rejects subsequent handshakes. The adapter also closes established
// streams and cancels their custody contexts; a ticket is not a revocation lease.
func (b *FTPSChannelBinding) Close() { b.phase.Store(2) }
