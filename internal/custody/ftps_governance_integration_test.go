//go:build integration

package custody_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type ftpsGovernanceMessage struct {
	State        string `json:"state"`
	Resumed      bool   `json:"resumed"`
	CaseCount    int    `json:"case_count"`
	AllResumed   bool   `json:"all_data_resumed"`
	FailureClass string `json:"failure_class"`
	Reason       string `json:"reason"`
}
type ftpsGovernanceRead struct {
	message ftpsGovernanceMessage
	err     error
}
type ftpsGovernancePeer struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  chan ftpsGovernanceRead
	cancel  context.CancelFunc
	waited  bool
}

func ftpsPassword(t *testing.T, reference string) string {
	t.Helper()
	secret, err := secure.ReadSecret(reference, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	return string(secret.Bytes)
}

func startFTPSGovernancePeer(t *testing.T, f *ftpsFixture, scenario string, extra map[string]any) *ftpsGovernancePeer {
	t.Helper()
	u, err := url.Parse(f.url)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"scenario": scenario, "port": number, "implicit": u.Scheme == "ftps", "certificate": f.cert, "username": f.f.a.Tenant + "/" + f.f.a.Partner, "password": ftpsPassword(t, f.token)}
	for key, value := range extra {
		settings[key] = value
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	ref := filepath.Join(t.TempDir(), "governance.json")
	if err = os.WriteFile(ref, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.f.ctx)
	p := &ftpsGovernancePeer{cancel: cancel, output: make(chan ftpsGovernanceRead, 1)}
	p.command = exec.CommandContext(ctx, "python3", filepath.Join("..", "..", "scripts", "ftps-governance-probe.py"), "--reference", ref)
	p.command.Stderr = io.Discard // Failures use bounded, redacted JSON on stdout.
	stdout, err := p.command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	p.input, err = p.command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = p.command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.cancel()
		_ = p.input.Close()
		if !p.waited {
			_ = p.command.Wait()
		}
	})
	go func() {
		decoder := json.NewDecoder(io.LimitReader(stdout, 16<<10))
		decoder.DisallowUnknownFields()
		for {
			var m ftpsGovernanceMessage
			err := decoder.Decode(&m)
			select {
			case p.output <- ftpsGovernanceRead{m, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *ftpsGovernancePeer) next(t *testing.T, state string) ftpsGovernanceMessage {
	t.Helper()
	select {
	case r := <-p.output:
		if r.err != nil || r.message.State != state {
			t.Fatalf("FTPS governance phase %s: %v; state=%s class=%s reason=%s", state, r.err, r.message.State, r.message.FailureClass, r.message.Reason)
		}
		return r.message
	case <-time.After(10 * time.Second):
		t.Fatalf("FTPS governance phase %s exceeded its deadline", state)
		return ftpsGovernanceMessage{}
	}
}
func (p *ftpsGovernancePeer) send(t *testing.T, action string) {
	t.Helper()
	if err := json.NewEncoder(p.input).Encode(map[string]string{"action": action}); err != nil {
		t.Fatal("send fixed governance phase", err)
	}
}
func (p *ftpsGovernancePeer) finish(t *testing.T, cases int) {
	t.Helper()
	m := p.next(t, "passed")
	if m.CaseCount != cases || !m.AllResumed {
		t.Fatal("governance peer did not prove all cases and resumed data")
	}
	err := p.command.Wait()
	p.waited = true
	if err != nil {
		t.Fatal("governance peer failed after its final result", err)
	}
}

func TestFTPSNativeTLSClientCredentialLifecycle(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			token, next := filepath.Join(t.TempDir(), "delegated.token"), filepath.Join(t.TempDir(), "rotated.token")
			for _, path := range []string{token, next} {
				if err := secure.WriteToken(path); err != nil {
					t.Fatal(err)
				}
			}
			oldPassword, nextPassword := ftpsPassword(t, token), ftpsPassword(t, next)
			id := secure.NewID()
			created, err := f.f.db.ChangeAccount(f.f.ctx, f.f.a, "ftps-create", store.AccountCommand{Operation: "create", ID: id, CredentialHash: secure.Digest([]byte(oldPassword)), Policy: &store.AccountPolicy{Label: "FTPS delegated writer", Root: "/", Permissions: []string{"read", "write", "list"}}})
			if err != nil || created.Account.AuthorityRevision != 1 {
				t.Fatal("create delegated FTPS account", err)
			}
			peer := startFTPSGovernancePeer(t, f, "credential-lifecycle", map[string]any{"password": oldPassword, "next_password": nextPassword, "observer_password": ftpsPassword(t, f.token)})
			if !peer.next(t, "writer-open-before-rotation").Resumed {
				t.Fatal("writer data did not resume authenticated control")
			}
			original, err := f.f.service.StatPath(f.f.ctx, f.f.a, "/guard.bin")
			if err != nil {
				t.Fatal(err)
			}
			assertUnchanged := func() {
				t.Helper()
				now, err := f.f.service.StatPath(f.f.ctx, f.f.a, "/guard.bin")
				if err != nil || *now != *original {
					t.Fatal("invalidated writer changed accepted namespace revision", err)
				}
				var count int
				// Only the original guard and the separately completed transfer
				// under the rotated credential may exist. Failed open writers
				// must not leave an accepted but unpublished file record.
				if err = f.f.admin.QueryRow(f.f.ctx, `SELECT count(*) FROM files WHERE tenant_id=$1 AND partner_id=$2`, f.f.a.Tenant, f.f.a.Partner).Scan(&count); err != nil || count != 2 {
					t.Fatal("invalidated writer committed file metadata", count, err)
				}
			}
			rotated, err := f.f.db.ChangeAccount(f.f.ctx, f.f.a, "ftps-rotate", store.AccountCommand{Operation: "rotate", ID: id, ExpectedRevision: created.Account.Revision, CredentialHash: secure.Digest([]byte(nextPassword))})
			if err != nil || rotated.Account.AuthorityRevision != 2 {
				t.Fatal("rotate active FTPS credential", err)
			}
			peer.send(t, "rotation-committed")
			if !peer.next(t, "writer-open-before-revocation").Resumed {
				t.Fatal("rotated session data did not resume its new control")
			}
			assertUnchanged()
			revoked, err := f.f.db.ChangeAccount(f.f.ctx, f.f.a, "ftps-revoke", store.AccountCommand{Operation: "revoke", ID: id, ExpectedRevision: rotated.Account.Revision})
			if err != nil || revoked.Account.State != "revoked" || revoked.Account.AuthorityRevision != 3 {
				t.Fatal("revoke active FTPS credential", err)
			}
			peer.send(t, "revocation-committed")
			peer.finish(t, 2)
			assertUnchanged()
			var events int
			if err = f.f.admin.QueryRow(f.f.ctx, `SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND resource_id=$3 AND kind='AccountChanged'`, f.f.a.Tenant, f.f.a.Partner, id).Scan(&events); err != nil || events != 3 {
				t.Fatal("missing governed account lifecycle events", events, err)
			}
		})
	}
}

func TestFTPSNativeTLSClientIntakeReleaseAndRevocation(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			s := &checks.Service{Custody: f.f.service}
			policy := checks.Policy{Schema: 1, Kind: "csv", MaxBytes: 1024, MaxRows: 10, MaxRecordBytes: 128, TimeoutSeconds: 2, Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 16}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 16, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}}
			if _, err := s.Register(f.f.ctx, f.f.a, "ftps-intake", checks.PolicyRequest{Definition: policy}); err != nil {
				t.Fatal(err)
			}
			peer := startFTPSGovernancePeer(t, f, "intake", nil)
			peer.next(t, "uploads-held")
			page, err := s.List(f.f.ctx, f.f.a, "", 10)
			if err != nil || len(page.Checks) != 2 {
				t.Fatal("FTPS uploads did not create exact intake holds", err)
			}
			ids := map[string]string{}
			for _, item := range page.Checks {
				if item.State != "held" {
					t.Fatal("FTPS acknowledged an upload outside its selected hold")
				}
				ids[item.Path] = item.FileID
				if _, _, err = f.f.service.Download(f.f.ctx, f.f.a, item.FileID); !errors.Is(err, store.ErrState) {
					t.Fatal("raw file ID bypassed FTPS intake hold", err)
				}
				if _, err = s.Run(f.f.ctx, f.f.a, item.FileID, "ftps-parse-"+item.FileID); err != nil {
					t.Fatal(err)
				}
			}
			good, err := s.Get(f.f.ctx, f.f.a, ids["/good.csv"])
			if err != nil || good.Check.State != "passed" || good.Check.Attempts != 1 {
				t.Fatal("valid FTPS CSV did not pass its exact check", err)
			}
			bad, err := s.Get(f.f.ctx, f.f.a, ids["/bad.csv"])
			if err != nil || bad.Check.State != "rejected" || bad.Check.Attempts != 1 || bad.Check.ReportHash != "" {
				t.Fatal("malformed FTPS CSV was not rejected without a release proof", err)
			}
			decision := func(c *store.FileCheck) checks.ReleaseDecision {
				t.Helper()
				var binding store.CheckBinding
				if err := json.Unmarshal(c.Binding, &binding); err != nil {
					t.Fatal(err)
				}
				return checks.ReleaseDecision{SHA256: binding.File.SHA256, PolicyHash: c.PolicyHash, ReportHash: c.ReportHash, Revision: c.Revision}
			}
			d := decision(good.Check)
			if d.SHA256 != secure.Digest([]byte("account,amount,day\n0001,1.01,2026-10-28\n")) {
				t.Fatal("check was not bound to the actual uploaded bytes")
			}
			wrong := d
			wrong.SHA256 = strings.Repeat("0", 64)
			if _, err = s.Release(f.f.ctx, f.f.a, good.Check.FileID, "ftps-wrong-release", wrong); !errors.Is(err, store.ErrRevision) {
				t.Fatal("changed approval digest released FTPS bytes", err)
			}
			badDecision := decision(bad.Check)
			badDecision.ReportHash = d.ReportHash // Another file's passing report grants no release.
			if _, err = s.Release(f.f.ctx, f.f.a, bad.Check.FileID, "ftps-bad-release", badDecision); !errors.Is(err, store.ErrState) {
				t.Fatal("another revision's passing report released rejected FTPS bytes", err)
			}
			peer.send(t, "checks-completed")
			peer.next(t, "passed-still-unreleased")
			if _, err = s.Release(f.f.ctx, f.f.a, good.Check.FileID, "ftps-release", d); err != nil {
				t.Fatal(err)
			}
			peer.send(t, "release-committed")
			peer.next(t, "only-approved-revision-published")
			p, err := s.Policy(f.f.ctx, f.f.a)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Revoke(f.f.ctx, f.f.a, "ftps-revoke-policy", checks.PolicyDecision{Hash: p.Hash, Version: p.Version, Revision: p.Revision}); err != nil {
				t.Fatal(err)
			}
			peer.send(t, "policy-revocation-committed")
			peer.finish(t, 4)
		})
	}
}
