package crypto

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHSessionSelectorRequiresExplicitTypedCommandAndPreservesSubsystemOnlyDefault(t *testing.T) {
	handler := func(context.Context, SSHPrincipal, io.ReadWriteCloser) error { return nil }
	selected := 0
	commands := func(raw string) (SSHSubsystem, error) {
		selected++
		if raw != "scp -t /exact.dat" {
			return nil, errors.New("not the supported literal protocol command")
		}
		return handler, nil
	}
	exec := ssh.Marshal(struct{ Command string }{"scp -t /exact.dat"})
	if _, ok := selectSSHSession("exec", exec, handler, nil); ok {
		t.Fatal("default SFTP-only transport accepted an exec")
	}
	if _, ok := selectSSHSession("exec", exec, handler, commands); !ok || selected != 1 {
		t.Fatal("explicit typed legacy protocol was not selected")
	}
	if _, ok := selectSSHSession("subsystem", ssh.Marshal(struct{ Name string }{"sftp"}), handler, commands); !ok || selected != 1 {
		t.Fatal("legacy opt-in changed ordinary subsystem selection")
	}
	for _, kind := range []string{"shell", "env", "pty-req", "auth-agent-req@openssh.com", "window-change"} {
		if _, ok := selectSSHSession(kind, exec, handler, commands); ok {
			t.Fatal("non-protocol command request accepted", kind)
		}
	}
	for _, payload := range [][]byte{nil, {0, 0, 0, 255}, append(append([]byte{}, exec...), 0), ssh.Marshal(struct{ Command string }{strings.Repeat("a", 2049)}), ssh.Marshal(struct{ Command string }{"sh -c true"})} {
		if _, ok := selectSSHSession("exec", payload, handler, commands); ok {
			t.Fatal("malformed,oversized or unsupported command selected")
		}
	}
}
