//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// A stock OpenSSH daemon owns its own filesystem. The product's inbound SFTP
// server deliberately does not promise the fsync/hardlink sender contract.
type mixedStockReceiver struct {
	connection ConnectionView
	directory  string
	client     string
	knownHosts string
	user       string
	port       string
	log        string
}

func mixedReceiverCommand(t *testing.T, f *fixture, name string, args ...string) []byte {
	t.Helper()
	output, err := exec.CommandContext(f.ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("stock receiver command %s failed; output_sha256=%s", filepath.Base(name), secure.Digest(output))
	}
	return output
}

func newMixedStockReceiver(t *testing.T, f *fixture) *mixedStockReceiver {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("stock receiver qualification requires an unprivileged account")
	}
	// Keep authorized_keys beneath the private workspace, rather than a
	// world-writable temporary ancestor. StrictModes stays enabled.
	base, err := filepath.Abs(filepath.Join("..", "..", ".private"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(base, "freightctl-mixed-stock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
		}
	})
	r := &mixedStockReceiver{directory: filepath.Join(dir, "inbox"), client: filepath.Join(dir, "client"), log: filepath.Join(dir, "receiver.log")}
	if err = os.Mkdir(r.directory, 0700); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "host")
	for _, path := range []string{host, r.client} {
		mixedReceiverCommand(t, f, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path)
	}
	public, err := os.ReadFile(r.client + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(dir, "authorized_keys")
	if err = os.WriteFile(authorized, append([]byte("restrict "), public...), 0600); err != nil {
		t.Fatal(err)
	}
	r.user = strings.TrimSpace(string(mixedReceiverCommand(t, f, "id", "-un")))
	if r.user == "" || strings.ContainsAny(r.user, " \t\r\n\"\\") {
		t.Fatal("unsupported stock receiver account name")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_, r.port, err = net.SplitHostPort(address)
	listener.Close()
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
HostKey %s
PidFile %s
AuthorizedKeysFile %s
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
PermitRootLogin no
AllowUsers %s
StrictModes yes
PermitTTY no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no
MaxSessions 1
MaxStartups 2
LoginGraceTime 5
Subsystem sftp internal-sftp
ForceCommand internal-sftp -d %s
LogLevel VERBOSE
`, r.port, strconv.Quote(host), strconv.Quote(filepath.Join(dir, "receiver.pid")), strconv.Quote(authorized), r.user, strconv.Quote(r.directory))
	configPath := filepath.Join(dir, "sshd_config")
	if err = os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	mixedReceiverCommand(t, f, "/usr/sbin/sshd", "-t", "-f", configPath)
	log, err := os.OpenFile(r.log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", configPath)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		log.Close()
		t.Fatal("cannot start task-owned stock receiver")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		// Signal only this daemon's dedicated process group, including any
		// authenticated child. Never stop a system or another task's daemon.
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		log.Close()
	})
	ready := false
	for i := 0; i < 100; i++ {
		select {
		case err := <-done:
			done <- err
			t.Fatal("task-owned stock receiver exited before readiness")
		default:
		}
		connection, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			connection.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("task-owned stock receiver readiness deadline")
	}
	hostPublic, err := os.ReadFile(host + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	r.knownHosts = filepath.Join(dir, "known_hosts")
	if err = os.WriteFile(r.knownHosts, append([]byte("[127.0.0.1]:"+r.port+" "), hostPublic...), 0600); err != nil {
		t.Fatal(err)
	}
	registered, err := f.s.RegisterConnection(f.ctx, f.scope, "mixed-stock-connection", ConnectionRequest{Address: address, User: r.user, Directory: r.directory, HostPublicFile: host + ".pub", KeyFile: r.client, KeyPublicFile: r.client + ".pub"})
	if err != nil || json.Unmarshal(registered.Resource, &r.connection) != nil {
		t.Fatal("stock connection registration failed", err)
	}
	return r
}

func (r *mixedStockReceiver) sessions(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Count(data, []byte("Accepted publickey for "))
}

func (r *mixedStockReceiver) requireBytes(t *testing.T, f *fixture, filename string) {
	t.Helper()
	final := filepath.Join(r.directory, filename)
	data, err := os.ReadFile(final)
	if err != nil || !bytes.Equal(data, []byte("abc")) {
		t.Fatal("stock receiver filesystem bytes differ", err)
	}
	destination := filepath.Join(filepath.Dir(r.directory), "independent-readback")
	batch := filepath.Join(filepath.Dir(r.directory), "readback.batch")
	if err = os.WriteFile(batch, []byte("get "+strconv.Quote(final)+" "+strconv.Quote(destination)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mixedReceiverCommand(t, f, "sftp", "-F", "/dev/null", "-P", r.port, "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile="+r.knownHosts, "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-i", r.client, "-b", batch, r.user+"@127.0.0.1")
	data, err = os.ReadFile(destination)
	if err != nil || !bytes.Equal(data, []byte("abc")) {
		t.Fatal("independent stock SFTP readback differs", err)
	}
}

func TestMixedRegisteredFTPSAndStockSFTPKeepOrderConsentAndReceipts(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		for _, schema := range []int{1, 2} {
			for _, first := range []string{"sftp", "ftps"} {
				t.Run(fmt.Sprintf("%s/schema%d/%s-first", mode, schema, first), func(t *testing.T) {
					f, sender, reviewer, account := outboundFixture(t)
					ftpReceiver, ftpSpec, ftpListener := governedFTPSReceiver(t, mode == "implicit")
					ftpConnection := registeredFTPSConnection(t, f, ftpSpec)
					ssh := newMixedStockReceiver(t, f)
					ref := func(c ConnectionView) Reference { return Reference{ID: c.ID, Version: c.Version, Hash: c.Hash} }
					steps := []Step{{ID: "ssh", Kind: "sftp.deliver", Connection: ref(ssh.connection), Filename: "ssh.csv"}, {ID: "ftp", Kind: "ftps.deliver", Connection: ref(ftpConnection), Filename: "ftp.csv"}}
					if first == "ftps" {
						steps[0], steps[1] = steps[1], steps[0]
					}
					definition := Definition{Schema: schema, Name: "Mixed registered settlement", Steps: steps}
					if schema == 2 {
						definition.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: steps[0].ID}, {Kind: "deliver", Step: steps[1].ID}}}
					}
					wf := f.approved(t, definition)
					request := RunRequest{Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID}
					result, err := f.s.Run(f.ctx, f.scope, "mixed-run", request)
					if err != nil {
						t.Fatal(err)
					}
					var run store.WorkflowRun
					if json.Unmarshal(result.Resource, &run) != nil {
						t.Fatal("mixed run receipt")
					}
					status, err := f.s.Status(f.ctx, f.scope, run.ID)
					if err != nil || len(status.Steps) != 2 || status.Steps[0].ID != steps[0].ID || status.Steps[1].ID != steps[1].ID {
						t.Fatal("mixed run lost approved order", err)
					}
					deliveries := make([]*store.Delivery, 2)
					for i, step := range status.Steps {
						deliveries[i], err = sender.Status(f.ctx, f.scope, step.DeliveryID)
						if err != nil {
							t.Fatal(err)
						}
					}
					if _, err = f.s.Work(f.ctx, f.scope, run.ID, "mixed-first"); !errors.Is(err, store.ErrDispatchApproval) {
						t.Fatal("mixed first step bypassed consent", err)
					}
					if ftpListener.contacts.Load() != 0 || ssh.sessions(t) != 0 {
						t.Fatal("unapproved mixed run authenticated to a receiver")
					}
					reviewAt := func(i int) store.OutboundDispatchSummary {
						d := deliveries[i]
						preview, review, _ := proposeDispatch(t, f, sender, d, account.ID, fmt.Sprintf("mixed-review-%d", i))
						binding := preview.Definition.Effect.Workflow
						if binding == nil || binding.RunID != run.ID || binding.StepID != steps[i].ID || binding.ConnectionHash != steps[i].Connection.Hash {
							t.Fatal("mixed independent review lost exact binding")
						}
						return review
					}
					if _, err = sender.PreviewDispatchReview(f.ctx, f.scope, delivery.DispatchSelection{DeliveryID: deliveries[1].ID, DispatchDecision: delivery.DispatchDecision{Hash: deliveries[1].DefinitionHash, Revision: deliveries[1].Revision}, ReviewerID: account.ID}); !errors.Is(err, store.ErrState) {
						t.Fatal("later review bypassed the incomplete predecessor", err)
					}
					if _, _, err = decideDispatch(t, f, sender, reviewer, reviewAt(0), "approve", "mixed-first-consent"); err != nil {
						t.Fatal(err)
					}
					if _, err = sender.Work(f.ctx, f.scope, deliveries[1].ID); !errors.Is(err, store.ErrState) {
						t.Fatal("direct sender bypassed mixed predecessor", err)
					}
					firstResult, err := f.s.Work(f.ctx, f.scope, run.ID, "mixed-first")
					if err != nil || !firstResult.Replayed || firstResult.Status.Steps[0].State != "succeeded" || firstResult.Status.Steps[1].State != "queued" {
						t.Fatal("first mixed dispatch advanced wrong steps", err)
					}
					ftpContacts, sshSessions := ftpListener.contacts.Load(), ssh.sessions(t)
					replayed, err := f.s.Work(f.ctx, f.scope, run.ID, "mixed-first")
					if err != nil || !replayed.Replayed || replayed.Dispatch != firstResult.Dispatch || replayed.Status.Steps[1].State != "queued" || ftpListener.contacts.Load() != ftpContacts || ssh.sessions(t) != sshSessions {
						t.Fatal("saved mixed worker key resent or advanced", err)
					}
					untouched, err := sender.Status(f.ctx, f.scope, deliveries[1].ID)
					if err != nil || untouched.Attempts != 0 || untouched.Fence != 0 {
						t.Fatal("later mixed step consumed sending identity", err)
					}
					if _, err = f.s.Work(f.ctx, f.scope, run.ID, "mixed-second"); !errors.Is(err, store.ErrDispatchApproval) || ftpListener.contacts.Load() != ftpContacts || ssh.sessions(t) != sshSessions {
						t.Fatal("first consent authorized the other protocol", err)
					}
					if first == "sftp" {
						if ftpContacts != 0 {
							t.Fatal("later FTPS receiver contacted before its turn")
						}
					} else {
						entries, err := os.ReadDir(ssh.directory)
						if err != nil || len(entries) != 0 || sshSessions != 0 {
							t.Fatal("later SFTP receiver touched before its turn", err)
						}
					}
					if _, _, err = decideDispatch(t, f, sender, reviewer, reviewAt(1), "approve", "mixed-second-consent"); err != nil {
						t.Fatal(err)
					}
					secondResult, err := f.s.Work(f.ctx, f.scope, run.ID, "mixed-second")
					if err != nil || !secondResult.Replayed || secondResult.Status.ObservedState != "succeeded" {
						t.Fatal("mixed workflow did not finish", err)
					}
					for i, d := range deliveries {
						current, err := sender.Status(f.ctx, f.scope, d.ID)
						if err != nil || current.Attempts != 1 || current.Fence != 1 {
							t.Fatal("mixed intent identity differs", err)
						}
						var receipt map[string]any
						if json.Unmarshal(current.Observation, &receipt) != nil || receipt["business_acceptance"] != "unknown" || receipt["sha256"] != f.file.SHA256 || receipt["size_bytes"] != float64(f.file.Size) {
							t.Fatal("mixed receipt lost original source or invented business acceptance")
						}
						if steps[i].Kind == "sftp.deliver" {
							if receipt["file_fsync_acknowledged"] != true {
								t.Fatal("stock SFTP did not retain its stronger persistence contract")
							}
							ssh.requireBytes(t, f, d.ID+"-ssh.csv")
						} else {
							if receipt["protocol"] != "ftps" || receipt["file_fsync_acknowledged"] != false || receipt["rename_acknowledged"] != true {
								t.Fatal("FTPS inherited unsupported SFTP promises")
							}
							readReceiverBytes(t, ftpReceiver, "/inbox/"+d.ID+"-ftp.csv")
						}
					}
					ftpContacts, sshSessions = ftpListener.contacts.Load(), ssh.sessions(t)
					if replayed, err = f.s.Work(f.ctx, f.scope, run.ID, "mixed-second"); err != nil || !replayed.Replayed || replayed.Dispatch != secondResult.Dispatch || ftpListener.contacts.Load() != ftpContacts || ssh.sessions(t) != sshSessions {
						t.Fatal("completed mixed workflow resent", err)
					}
				})
			}
		}
	}
}
