package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHPublic struct {
	Wire        []byte
	Fingerprint string
}
type SSHPrincipal struct {
	Tenant, Partner, Actor, Fingerprint string
	AuthorityRevision                   int64
}
type SSHOptions struct {
	HostKeyFile             string
	MaxConnections          int
	SessionLimit, IdleLimit time.Duration
}
type SSHAuthorizer func(context.Context, string, SSHPublic) (SSHPrincipal, error)
type SSHSubsystem func(context.Context, SSHPrincipal, io.ReadWriteCloser) error

func ValidateSSHPublic(public SSHPublic) (SSHPublic, error) {
	if len(public.Wire) < 16 || len(public.Wire) > 16384 {
		return SSHPublic{}, errors.New("invalid SSH public wire length")
	}
	key, err := ssh.ParsePublicKey(public.Wire)
	if err != nil {
		return SSHPublic{}, errors.New("invalid SSH public wire")
	}
	if err = publicPolicy(key); err != nil {
		return SSHPublic{}, err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	if public.Fingerprint != fingerprint {
		return SSHPublic{}, errors.New("SSH public fingerprint differs")
	}
	return SSHPublic{Wire: key.Marshal(), Fingerprint: fingerprint}, nil
}

func publicPolicy(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519:
		return nil
	case ssh.KeyAlgoECDSA256:
		if k, ok := key.(ssh.CryptoPublicKey); ok {
			if _, ok = k.CryptoPublicKey().(*ecdsa.PublicKey); ok {
				return nil
			}
		}
	case ssh.KeyAlgoRSA:
		if k, ok := key.(ssh.CryptoPublicKey); ok {
			if r, ok := k.CryptoPublicKey().(*rsa.PublicKey); ok && r.N.BitLen() >= 3072 && r.N.BitLen() <= 8192 {
				return nil
			}
		}
	}
	return errors.New("SSH public key violates the configured algorithm policy")
}
func ReadSSHPublic(path string) (SSHPublic, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 16384 {
		return SSHPublic{}, errors.New("SSH public reference must be a bounded regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return SSHPublic{}, errors.New("cannot open SSH public reference")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 {
		return SSHPublic{}, errors.New("SSH public reference exceeds its bound")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return SSHPublic{}, errors.New("one SSH public key is required; embedded authorization options cannot grant policy")
	}
	if err = publicPolicy(key); err != nil {
		return SSHPublic{}, err
	}
	return SSHPublic{Wire: key.Marshal(), Fingerprint: ssh.FingerprintSHA256(key)}, nil
}
func GenerateSSHHostIdentity(privatePath, publicPath string) error {
	if privatePath == publicPath {
		return errors.New("SSH identity paths must differ")
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("SSH identity targets must be new files")
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer Clear(private)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	defer Clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer Clear(encoded)
	pub, err := ssh.NewPublicKey(public)
	if err != nil {
		return err
	}
	if err = writeExclusive(privatePath, encoded); err != nil {
		return err
	}
	return writeExclusive(publicPath, ssh.MarshalAuthorizedKey(pub))
}

type idleConn struct {
	net.Conn
	deadline time.Time
	idle     time.Duration
	active   atomic.Bool
}

func (c *idleConn) touch() {
	next := time.Now().Add(c.idle)
	if next.After(c.deadline) {
		next = c.deadline
	}
	_ = c.Conn.SetDeadline(next)
}
func (c *idleConn) Read(p []byte) (int, error) {
	if c.active.Load() {
		c.touch()
	}
	return c.Conn.Read(p)
}
func (c *idleConn) Write(p []byte) (int, error) {
	if c.active.Load() {
		c.touch()
	}
	return c.Conn.Write(p)
}

// ServeSFTP owns SSH cryptography and allows exactly one SFTP subsystem per
// connection. No shell, command, environment, forwarding or agent channel exists.
func ServeSFTP(ctx context.Context, listener net.Listener, options SSHOptions, authorize SSHAuthorizer, subsystem SSHSubsystem) error {
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		return errors.New("development SSH listener must be loopback")
	}
	secret, err := ReadSecret(options.HostKeyFile, 16384)
	if err != nil {
		return err
	}
	defer secret.Close()
	signer, err := ssh.ParsePrivateKey(secret.Bytes)
	if err != nil {
		return errors.New("cannot parse SSH host identity")
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return errors.New("initial SSH host identity policy requires Ed25519")
	}
	if options.MaxConnections < 1 || options.MaxConnections > 1024 {
		return errors.New("invalid SSH connection budget")
	}
	if options.SessionLimit <= 0 {
		options.SessionLimit = 5 * time.Minute
	}
	if options.IdleLimit <= 0 {
		options.IdleLimit = 30 * time.Second
	}
	algorithms := ssh.SupportedAlgorithms()
	config := &ssh.ServerConfig{Config: ssh.Config{KeyExchanges: algorithms.KeyExchanges, Ciphers: algorithms.Ciphers, MACs: algorithms.MACs}, MaxAuthTries: 3, PublicKeyAuthAlgorithms: algorithms.PublicKeyAuths, ServerVersion: "SSH-2.0-freightctl"}
	config.AddHostKey(signer)
	config.PublicKeyCallback = func(metadata ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if len(metadata.User()) > 128 {
			return nil, errors.New("SSH identity denied")
		}
		if err := publicPolicy(key); err != nil {
			return nil, errors.New("SSH identity denied")
		}
		authCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		principal, err := authorize(authCtx, metadata.User(), SSHPublic{Wire: key.Marshal(), Fingerprint: ssh.FingerprintSHA256(key)})
		if err != nil {
			return nil, errors.New("SSH identity denied")
		}
		return &ssh.Permissions{ExtraData: map[any]any{"freightctl": principal}}, nil
	}
	var workers sync.WaitGroup
	slots := make(chan struct{}, options.MaxConnections)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-stop:
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			workers.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		workers.Add(1)
		go func(raw net.Conn) {
			defer workers.Done()
			defer func() { <-slots }()
			defer raw.Close()
			sessionCtx, cancel := context.WithTimeout(ctx, options.SessionLimit)
			defer cancel()
			connectionStop := make(chan struct{})
			defer close(connectionStop)
			go func() {
				select {
				case <-sessionCtx.Done():
					raw.Close()
				case <-connectionStop:
				}
			}()
			_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
			deadline, _ := sessionCtx.Deadline()
			wrapped := &idleConn{Conn: raw, deadline: deadline, idle: options.IdleLimit}
			secure, channels, requests, err := ssh.NewServerConn(wrapped, config)
			if err != nil {
				return
			}
			var children sync.WaitGroup
			defer func() { cancel(); _ = secure.Close(); children.Wait() }()
			if secure.Permissions == nil {
				return
			}
			principal, ok := secure.Permissions.ExtraData["freightctl"].(SSHPrincipal)
			if !ok {
				return
			}
			wrapped.active.Store(true)
			wrapped.touch()
			go ssh.DiscardRequests(requests)
			used := false
			for incoming := range channels {
				if used || incoming.ChannelType() != "session" {
					_ = incoming.Reject(ssh.Prohibited, "only one SFTP session is permitted")
					continue
				}
				used = true
				channel, channelRequests, err := incoming.Accept()
				if err != nil {
					return
				}
				children.Add(1)
				go func() {
					defer children.Done()
					defer channel.Close()
					for request := range channelRequests {
						var selected struct{ Name string }
						if request.Type != "subsystem" || len(request.Payload) > 128 || ssh.Unmarshal(request.Payload, &selected) != nil || selected.Name != "sftp" {
							_ = request.Reply(false, nil)
							continue
						}
						_ = request.Reply(true, nil)
						go func() {
							for extra := range channelRequests {
								_ = extra.Reply(false, nil)
							}
						}()
						err := subsystem(sessionCtx, principal, channel)
						status := uint32(0)
						if err != nil && !errors.Is(err, io.EOF) {
							status = 1
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						_ = channel.CloseWrite()
						return
					}
				}()
			}
		}(connection)
	}
}
