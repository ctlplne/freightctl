//go:build integration && scppeer

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/sftpd"
	"github.com/ctlplne/freightctl/internal/store"
)

// All subprocesses and peers run only on the authorized native GitHub runner.
func TestLegacySCPOpenSSHNativeBytesAbortRevocationAndSFTPDefault(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Fatal("stock legacy SCP requires its authorized native GitHub environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("native source differs from Actions candidate")
	}
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	peerEnv := append(os.Environ(), "SSH_AUTH_SOCK=", "SSH_ASKPASS=", "SSH_ASKPASS_REQUIRE=never", "DISPLAY=")
	run := func(program string, args []string, success bool) {
		t.Helper()
		logPath := filepath.Join(private, "peer-"+secure.NewID()+".log")
		log, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), program, args...)
		command.Env, command.Stdout, command.Stderr = peerEnv, log, log
		err = command.Run()
		log.Close()
		if (err == nil) != success {
			raw, _ := os.ReadFile(logPath)
			t.Fatalf("native peer outcome differs;program=%s;expected-success=%t;private-log-SHA256=%s", program, success, secure.Digest(raw))
		}
	}
	service, scope, admin, https := browserAPI(t, 10*time.Minute)
	adminReference := browserAdminReference(t, service)
	identity, err := service.DB.Identity(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(private, "owner.token")
	if err = os.WriteFile(tokenPath, admin.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	clientKey, clientPublic := filepath.Join(private, "client.key"), filepath.Join(private, "client.key.pub")
	run("ssh-keygen", []string{"-q", "-t", "ed25519", "-N", "", "-f", clientKey}, true)
	public, err := secure.ReadSSHPublic(clientPublic)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.ManageSSHKey(t.Context(), adminReference, tokenPath, scope.Tenant, scope.Partner, public, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKey, hostPublic := filepath.Join(private, "host.key"), filepath.Join(private, "host.pub")
	if err = secure.GenerateSSHHostIdentity(hostKey, hostPublic); err != nil {
		t.Fatal(err)
	}
	hostWire, err := os.ReadFile(hostPublic)
	if err != nil {
		t.Fatal(err)
	}
	transport, err := sftpd.New(service, 2)
	if err != nil {
		t.Fatal(err)
	}
	start := func(legacy bool) (string, string, func()) {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(listener.Addr().String())
		known := filepath.Join(private, "known-"+port)
		if err = os.WriteFile(known, append([]byte("[127.0.0.1]:"+port+" "), hostWire...), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		finished := make(chan error, 1)
		options := secure.SSHOptions{HostKeyFile: hostKey, MaxConnections: 4, SessionLimit: time.Minute, IdleLimit: 10 * time.Second}
		if legacy {
			options.LegacySCP = transport.LegacySCP
		}
		go func() {
			finished <- secure.ServeSFTP(ctx, listener, options, service.DB.AllowSSHKey, transport.Session)
		}()
		stop := func() {
			cancel()
			listener.Close()
			if err := <-finished; err != nil {
				t.Error("owned SSH server did not shut down cleanly")
			}
		}
		t.Cleanup(stop)
		return port, known, stop
	}
	options := func(known, key string) []string {
		return []string{"-F", "/dev/null", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + known, "-oGlobalKnownHostsFile=/dev/null", "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oClearAllForwardings=yes", "-oProxyCommand=none", "-oProxyJump=none", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oConnectTimeout=5", "-i", key}
	}
	payload := bytes.Repeat([]byte("inert artifact;receiving grants no execution\n"), 4000)
	source, second := filepath.Join(private, "source.dat"), filepath.Join(private, "second.dat")
	for _, file := range []string{source, second} {
		if err = os.WriteFile(file, payload, 0600); err != nil {
			t.Fatal(err)
		}
	}
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	headers := map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}
	verifyPath := func(path string, want []byte) store.PathEntry {
		t.Helper()
		_, raw := exchangeAPIRequest(t, https, "GET", prefix+"/namespace/stat?path="+path, nil, headers, nil, 200)
		var entry store.PathEntry
		if json.Unmarshal(raw, &entry) != nil || entry.Kind != "file" || entry.Size != int64(len(want)) {
			t.Fatal("native accepted path metadata differs")
		}
		_, received := exchangeAPIRequest(t, https, "GET", prefix+"/files/"+entry.FileID, nil, headers, nil, 200)
		if !bytes.Equal(received, want) {
			t.Fatal("independent HTTPS receiver bytes differ")
		}
		return entry
	}
	countFiles := func() int {
		t.Helper()
		transaction, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer transaction.Tx.Rollback(t.Context())
		var count int
		if err = transaction.Tx.QueryRow(t.Context(), `SELECT count(*) FROM files`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	port, known, _ := start(false)
	args := append([]string{"-q", "-B", "-P", port}, options(known, clientKey)...)
	run("scp", append(append([]string{}, args...), source, identity.SSHUsername+"@127.0.0.1:/modern-default.dat"), true)
	verifyPath("/modern-default.dat", payload)
	run("scp", append(append([]string{"-O"}, args...), source, identity.SSHUsername+"@127.0.0.1:/disabled-legacy.dat"), false)
	exchangeAPIRequest(t, https, "GET", prefix+"/namespace/stat?path=/disabled-legacy.dat", nil, headers, nil, 404)
	port, known, _ = start(true)
	args = append([]string{"-O", "-q", "-B", "-P", port}, options(known, clientKey)...)
	remote := identity.SSHUsername + "@127.0.0.1:"
	run("scp", append(append([]string{}, args...), source, remote+"/scp-private.dat"), true)
	original := verifyPath("/scp-private.dat", payload)
	download := filepath.Join(private, "independent-download")
	run("scp", append(append([]string{}, args...), remote+"/scp-private.dat", download), true)
	got, err := os.ReadFile(download)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("independent stock legacy SCP receiver bytes differ")
	}
	run("scp", append(append([]string{}, args...), source, second, remote+"/"), true)
	verifyPath("/source.dat", payload)
	verifyPath("/second.dat", payload)
	// Use the actual stock SSH stream to select incomplete/error terminators.
	// No synthetic custody service or protocol response is substituted.
	stream := func(target string, body []byte, declared int, terminator []byte, revoke bool) {
		t.Helper()
		before := countFiles()
		sshArgs := append([]string{"-T", "-p", port}, options(known, clientKey)...)
		sshArgs = append(sshArgs, identity.SSHUsername+"@127.0.0.1", "scp -t "+target)
		command := exec.CommandContext(t.Context(), "ssh", sshArgs...)
		command.Env = peerEnv
		stderr, err := os.OpenFile(filepath.Join(private, "stream-"+secure.NewID()+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer stderr.Close()
		command.Stderr = stderr
		input, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err = command.Start(); err != nil {
			t.Fatal("stock SSH stream did not start")
		}
		defer command.Process.Kill()
		reader := bufio.NewReader(output)
		ack := func() {
			value, err := reader.ReadByte()
			if err != nil || value != 0 {
				t.Fatal("actual SCP admission did not acknowledge")
			}
		}
		ack()
		if _, err = fmt.Fprintf(input, "C0600 %d input.dat\n", declared); err != nil {
			t.Fatal(err)
		}
		ack()
		if _, err = input.Write(body); err != nil {
			t.Fatal("native data stream write failed")
		}
		if revoke {
			if result, err := store.ManageSSHKey(t.Context(), adminReference, tokenPath, scope.Tenant, scope.Partner, secure.SSHPublic{}, registered.ID); err != nil || !result.Revoked {
				t.Fatal("ordinary SSH key revocation failed", err)
			}
		}
		if len(terminator) > 0 {
			_, _ = input.Write(terminator)
		}
		input.Close()
		// Zero here would incorrectly promise durable acceptance.
		last, readErr := reader.ReadByte()
		if readErr == nil && last == 0 {
			t.Fatal("aborted/withdrawn transfer received a durable acknowledgement")
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(reader, 2048))
		if err = command.Wait(); err == nil {
			t.Fatal("aborted/withdrawn transfer exited successfully")
		}
		exchangeAPIRequest(t, https, "GET", prefix+"/namespace/stat?path="+target, nil, headers, nil, 404)
		if countFiles() != before {
			t.Fatal("aborted/withdrawn transfer accepted a file")
		}
	}
	stream("/partial.dat", payload[:100], len(payload), nil, false)
	stream("/empty-abort.dat", nil, len(payload), nil, false)
	stream("/sender-error.dat", payload, len(payload), []byte("\x01sender failed\n"), false)
	// A confined actor cannot use an absolute command path to escape its root.
	cookie, csrf := loginBrowser(t, https, scope, admin)
	other, participant := exchangeAPIParticipant(t, https, prefix, cookie, csrf, []string{"read", "list"})
	if _, err = service.PathCommand(t.Context(), scope, "scp-confined-root", store.PathCommand{Operation: "mkdir", Path: "/confined"}); err != nil {
		t.Fatal(err)
	}
	if _, err = service.DB.ChangeAccount(t.Context(), scope, "scp-confined-policy", store.AccountCommand{Operation: "update", ID: participant.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "Confined SCP reader", Root: "/confined", Permissions: []string{"read", "list"}}}); err != nil {
		t.Fatal(err)
	}
	otherToken, otherKey := filepath.Join(private, "other.token"), filepath.Join(private, "other.key")
	if err = os.WriteFile(otherToken, other.Bytes, 0600); err != nil {
		t.Fatal(err)
	}
	run("ssh-keygen", []string{"-q", "-t", "ed25519", "-N", "", "-f", otherKey}, true)
	otherPublic, err := secure.ReadSSHPublic(otherKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ManageSSHKey(t.Context(), adminReference, otherToken, scope.Tenant, scope.Partner, otherPublic, ""); err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := service.DB.Identity(t.Context(), store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(other.Bytes)})
	if err != nil {
		t.Fatal(err)
	}
	foreignArgs := append([]string{"-O", "-q", "-B", "-P", port}, options(known, otherKey)...)
	run("scp", append(foreignArgs, otherIdentity.SSHUsername+"@127.0.0.1:/scp-private.dat", filepath.Join(private, "foreign-download")), false)
	// Real current intake accepts custody but never publishes the held path.
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "scp-required-intake", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	heldSource := filepath.Join(private, "held.csv")
	if err = os.WriteFile(heldSource, []byte("record\ninert\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run("scp", append(append([]string{}, args...), heldSource, remote+"/held.csv"), true)
	exchangeAPIRequest(t, https, "GET", prefix+"/namespace/stat?path=/held.csv", nil, headers, nil, 404)
	page, err := checking.List(t.Context(), scope, "", 10)
	if err != nil || len(page.Checks) != 1 || page.Checks[0].Path != "/held.csv" || page.Checks[0].State != "held" {
		t.Fatal("legacy acknowledgement did not retain exact intake hold", err)
	}
	if _, reader, err := service.Download(t.Context(), scope, page.Checks[0].FileID); !errors.Is(err, store.ErrState) {
		if reader != nil {
			reader.Close()
		}
		t.Fatal("held SCP artifact bytes became readable", err)
	}
	stream("/revoked.dat", payload, len(payload), []byte{0}, true)
	run("scp", append(append([]string{}, args...), remote+"/scp-private.dat", filepath.Join(private, "revoked-download")), false)
	for _, program := range []string{"ssh", "scp"} {
		binaryPath, err := exec.LookPath(program)
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.ReadFile(binaryPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("native stock peer;candidate=%s;architecture=%s;program=%s;binary-SHA256=%s", commit, runtime.GOARCH, program, secure.Digest(binary))
	}
	t.Logf("native legacy SCP file proof;candidate=%s;artifact=%s;bytes=%d;SHA256=%s;modern-default,legacy-byte-receivers,directory-files,abort,nonzero-terminator,confined-root,intake-hold,revocation passed;business-processing=unknown", commit, original.FileID, len(payload), secure.Digest(payload))
}
