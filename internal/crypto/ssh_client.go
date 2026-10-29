package crypto

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var sshUserPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

type SSHDestination struct {
	Address        string    `json:"address"`
	User           string    `json:"user"`
	Host           SSHPublic `json:"host"`
	KeyFile        string    `json:"key_reference"`
	KeyFingerprint string    `json:"key_fingerprint"`
}

func ValidateSSHDestination(d SSHDestination) error {
	host, port, err := net.SplitHostPort(d.Address)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 || strconv.Itoa(portNumber) != port || !sshUserPattern.MatchString(d.User) {
		return errors.New("development destination requires a numeric loopback address and a bounded SSH username")
	}
	if _, err = ValidateSSHPublic(d.Host); err != nil {
		return err
	}
	_, err = clientSigner(d)
	return err
}
func clientSigner(d SSHDestination) (ssh.Signer, error) {
	secret, err := ReadSecret(d.KeyFile, 16384)
	if err != nil {
		return nil, err
	}
	defer secret.Close()
	signer, err := ssh.ParsePrivateKey(secret.Bytes)
	if err != nil || publicPolicy(signer.PublicKey()) != nil || ssh.FingerprintSHA256(signer.PublicKey()) != d.KeyFingerprint {
		return nil, errors.New("SSH client identity differs from its approved reference")
	}
	return signer, nil
}

type sshClientStream struct {
	io.Reader
	io.Writer
	raw     net.Conn
	client  *ssh.Client
	session *ssh.Session
	once    sync.Once
	stop    chan struct{}
	done    chan struct{}
}

func (s *sshClientStream) Close() error {
	s.once.Do(func() { close(s.stop); _ = s.raw.Close(); _ = s.session.Close(); _ = s.client.Close(); <-s.done })
	return nil
}

// DialSFTP uses only the explicit key and pinned host wire. No SSH config, agent,
// password, DNS, command execution or forwarding is consulted.
func DialSFTP(ctx context.Context, d SSHDestination) (io.ReadWriteCloser, error) {
	if err := ValidateSSHDestination(d); err != nil {
		return nil, err
	}
	signer, err := clientSigner(d)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", d.Address)
	if err != nil {
		return nil, errors.New("SFTP receiver unavailable")
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
		deadline = v
	}
	wrapped := &idleConn{Conn: raw, deadline: deadline, idle: 15 * time.Second}
	wrapped.active.Store(true)
	wrapped.touch()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			raw.Close()
		case <-stop:
		}
	}()
	defer func() {
		if !success {
			close(stop)
			<-done
		}
	}()
	a := ssh.SupportedAlgorithms()
	cfg := &ssh.ClientConfig{Config: ssh.Config{KeyExchanges: a.KeyExchanges, Ciphers: a.Ciphers, MACs: a.MACs}, User: d.User, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: a.HostKeys, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		if publicPolicy(k) != nil || !bytes.Equal(k.Marshal(), d.Host.Wire) {
			return errors.New("receiver host identity differs")
		}
		return nil
	}}
	connection, channels, requests, err := ssh.NewClientConn(wrapped, d.Address, cfg)
	if err != nil {
		return nil, errors.New("receiver identity or SSH negotiation failed")
	}
	client := ssh.NewClient(connection, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, errors.New("SFTP session denied")
	}
	input, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	output, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, err
	}
	session.Stderr = io.Discard // Server text is untrusted and never becomes operator evidence or policy.
	if err = session.RequestSubsystem("sftp"); err != nil {
		session.Close()
		client.Close()
		return nil, errors.New("SFTP subsystem denied")
	}
	success = true
	return &sshClientStream{Reader: output, Writer: input, raw: raw, client: client, session: session, stop: stop, done: done}, nil
}
