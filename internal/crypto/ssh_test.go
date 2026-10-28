package crypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHPublicReferenceCannotSupplyPolicy(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "host.key"), filepath.Join(dir, "host.pub")
	if err := GenerateSSHHostIdentity(private, public); err != nil {
		t.Fatal(err)
	}
	key, err := ReadSSHPublic(public)
	if err != nil || key.Fingerprint == "" || len(key.Wire) == 0 {
		t.Fatal(key, err)
	}
	if err = GenerateSSHHostIdentity(private, public); err == nil {
		t.Fatal("host identity was overwritten")
	}
	data, err := os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{append([]byte(`command="/bin/sh" `), data...), append(append([]byte{}, data...), data...), []byte("invalid")} {
		bad := filepath.Join(dir, NewID())
		if err = os.WriteFile(bad, input, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadSSHPublic(bad); err == nil {
			t.Fatal("untrusted authorization options or multiple keys accepted")
		}
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(public, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSSHPublic(link); err == nil {
		t.Fatal("symlink public reference accepted")
	}
}

func TestSSHTransportOnlyRunsAuthenticatedSFTPAndJoinsShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	private, public := filepath.Join(dir, "host.key"), filepath.Join(dir, "host.pub")
	if err := GenerateSSHHostIdentity(private, public); err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	host, _, _, _, err := ssh.ParseAuthorizedKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(identity)
	signer, err := ssh.NewSignerFromKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered, exited := make(chan struct{}, 1), make(chan struct{}, 1)
	finished := make(chan error, 1)
	principal := SSHPrincipal{Tenant: NewID(), Partner: NewID(), Actor: NewID(), AuthorityRevision: 1}
	go func() {
		finished <- ServeSFTP(ctx, listener, SSHOptions{HostKeyFile: private, MaxConnections: 2, SessionLimit: 10 * time.Second, IdleLimit: 500 * time.Millisecond}, func(_ context.Context, user string, key SSHPublic) (SSHPrincipal, error) {
			if user != "registered" || !bytes.Equal(key.Wire, signer.PublicKey().Marshal()) {
				return SSHPrincipal{}, errors.New("denied")
			}
			return principal, nil
		}, func(session context.Context, got SSHPrincipal, stream io.ReadWriteCloser) error {
			if got != principal {
				return errors.New("wrong principal")
			}
			entered <- struct{}{}
			defer func() { exited <- struct{}{} }()
			b := make([]byte, 1)
			for {
				if _, err := io.ReadFull(stream, b); err != nil {
					<-session.Done()
					return err
				}
				if _, err := stream.Write(b); err != nil {
					return err
				}
			}
		})
	}()
	config := &ssh.ClientConfig{User: "wrong", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(host), Timeout: 3 * time.Second}
	if denied, err := ssh.Dial("tcp", listener.Addr().String(), config); err == nil {
		denied.Close()
		t.Fatal("wrong identity authenticated")
	}
	config.User = "registered"
	client, err := ssh.Dial("tcp", listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if c, _, err := client.OpenChannel("direct-tcpip", nil); err == nil {
		c.Close()
		t.Fatal("forwarding channel accepted")
	}
	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)
	if accepted, err := channel.SendRequest("exec", true, ssh.Marshal(struct{ Command string }{"true"})); err != nil || accepted {
		t.Fatal("exec request", accepted, err)
	}
	if accepted, err := channel.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"sftp"})); err != nil || !accepted {
		t.Fatal("subsystem request", accepted, err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("subsystem did not start")
	}
	// Activity must refresh the idle deadline. Total elapsed exceeds three idle windows.
	for i := 0; i < 8; i++ {
		if _, err = channel.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 1)
		if _, err = io.ReadFull(channel, b); err != nil || b[0] != byte(i) {
			t.Fatal("active session expired", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	client.Close()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("connection cleanup did not cancel subsystem")
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transport did not join shutdown")
	}
}
