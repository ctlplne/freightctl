//go:build integration

package custody_test

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestFTPSNativeTLSClientUploadTicketRecovery(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPSCheckpoint(t, implicit, 64<<10)
			s := &checks.Service{Custody: f.f.service}
			policy := checks.Policy{Schema: 1, Kind: "csv", MaxBytes: 1 << 20, MaxRows: 20000, MaxRecordBytes: 128, TimeoutSeconds: 5, Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 16}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 16, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}}
			if _, err := s.Register(f.f.ctx, f.f.a, "ticket-policy", checks.PolicyRequest{Definition: policy}); err != nil {
				t.Fatal(err)
			}
			payload := []byte("account,amount,day\n" + strings.Repeat("0001,1.01,2026-10-28\n", 10000))
			created, err := f.f.service.CreateUpload(f.f.ctx, f.f.a, "ticket-create", custody.CreateUpload{Path: "/recovered.csv", Size: int64(len(payload)), SHA256: secure.Digest(payload)})
			if err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(t.TempDir(), "other.token")
			if err = secure.WriteToken(foreign); err != nil {
				t.Fatal(err)
			}
			if err = store.Provision(f.f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), f.f.a.Tenant, f.f.a.Partner, foreign); err != nil {
				t.Fatal(err)
			}
			peer := startFTPSGovernancePeer(t, f, "upload-ticket", map[string]any{"ticket": created.Upload.FTPSPath, "foreign_password": ftpsPassword(t, foreign)})
			peer.next(t, "ticket-checkpoint-open")
			until := time.Now().Add(5 * time.Second)
			for {
				v, e := f.f.service.UploadStatus(f.f.ctx, f.f.a, created.Upload.ID)
				if e != nil {
					t.Fatal(e)
				}
				if v.Offset == 64<<10 && v.Chunks == 1 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("FTPS did not commit exactly one durable checkpoint")
				}
				time.Sleep(10 * time.Millisecond)
			}
			peer.send(t, "interrupt-now")
			peer.next(t, "ticket-interrupted")
			f.restart(t) // Rejoin all old handles before serving the same storage/database.
			if _, err = f.f.service.StatPath(f.f.ctx, f.f.a, "/recovered.csv"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("checkpoint was published", err)
			}
			peer.send(t, "server-restarted")
			peer.next(t, "ticket-data-finished")
			until = time.Now().Add(5 * time.Second)
			var completed *custody.UploadView
			for {
				completed, err = f.f.service.UploadStatus(f.f.ctx, f.f.a, created.Upload.ID)
				if err != nil {
					t.Fatal(err)
				}
				if completed.State == "completed" {
					break
				}
				if time.Now().After(until) {
					t.Fatal("clean resumed data did not complete its durable ticket")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if completed.Offset != int64(len(payload)) || completed.Acceptance != "durable-held-pending-checks-and-release" || completed.FileID == "" {
				t.Fatal("ticket receipt is not exact held acceptance")
			}
			peer.send(t, "discard-final-reply")
			peer.next(t, "ticket-final-reply-unobserved")
			replay, err := f.f.service.CompleteUpload(f.f.ctx, f.f.a, created.Upload.ID, "sftp-complete-"+created.Upload.ID)
			if err != nil || !replay.Replayed || replay.Upload.FileID != completed.FileID {
				t.Fatal("lost final reply did not recover the original completion", err)
			}
			peer.send(t, "receipt-inspected")
			peer.next(t, "ticket-completed-held")
			var accepted int
			if err = f.f.admin.QueryRow(f.f.ctx, "SELECT count(*) FROM files WHERE tenant_id=$1 AND partner_id=$2", f.f.a.Tenant, f.f.a.Partner).Scan(&accepted); err != nil || accepted != 1 {
				t.Fatal("completion replay created another accepted revision", err)
			}
			if _, err = s.Run(f.f.ctx, f.f.a, completed.FileID, "ticket-check"); err != nil {
				t.Fatal(err)
			}
			view, err := s.Get(f.f.ctx, f.f.a, completed.FileID)
			if err != nil || view.Check.State != "passed" {
				t.Fatal("resumed ticket did not pass exact CSV validation", err)
			}
			var binding store.CheckBinding
			if err = json.Unmarshal(view.Check.Binding, &binding); err != nil {
				t.Fatal(err)
			}
			if binding.File.SHA256 != secure.Digest(payload) || binding.File.Size != int64(len(payload)) {
				t.Fatal("ticket completion changed exact bytes")
			}
			if _, err = s.Release(f.f.ctx, f.f.a, completed.FileID, "ticket-release", checks.ReleaseDecision{SHA256: binding.File.SHA256, PolicyHash: view.Check.PolicyHash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}); err != nil {
				t.Fatal(err)
			}
			peer.send(t, "release-committed")
			peer.finish(t, 6)
		})
	}
}

func TestFTPSStockLFTPUploadTicket(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			s := &checks.Service{Custody: f.f.service}
			policy := checks.Policy{Schema: 1, Kind: "csv", MaxBytes: 1 << 20, MaxRows: 20000, MaxRecordBytes: 128, TimeoutSeconds: 5, Columns: []checks.Column{{Name: "account", Type: "text", Required: true, MaxBytes: 16}, {Name: "amount", Type: "decimal", Required: true, MaxBytes: 16, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true, MaxBytes: 10}}}
			if _, err := s.Register(f.f.ctx, f.f.a, "stock-ticket-policy", checks.PolicyRequest{Definition: policy}); err != nil {
				t.Fatal(err)
			}
			payload := []byte("account,amount,day\n" + strings.Repeat("0001,1.01,2026-10-28\n", 10000))
			created, err := f.f.service.CreateUpload(f.f.ctx, f.f.a, "stock-ticket-create", custody.CreateUpload{Path: "/stock-ticket.csv", Size: int64(len(payload)), SHA256: secure.Digest(payload)})
			if err != nil {
				t.Fatal(err)
			}
			prefix := payload[:64<<10]
			if _, err = f.f.service.AppendUpload(f.f.ctx, f.f.a, created.Upload.ID, "stock-ticket-prefix", 0, int64(len(prefix)), secure.Digest(prefix), bytes.NewReader(prefix)); err != nil {
				t.Fatal(err)
			}
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
			dir := t.TempDir()
			source := filepath.Join(dir, "payload.csv")
			if err = os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			probe := func(phase string, cases int) {
				t.Helper()
				settings := map[string]any{"port": number, "implicit": implicit, "certificate": f.cert, "source": source, "username": f.f.a.Tenant + "/" + f.f.a.Partner, "password": ftpsPassword(t, f.token), "ticket": created.Upload.FTPSPath, "ticket_phase": phase}
				data, e := json.Marshal(settings)
				if e != nil {
					t.Fatal(e)
				}
				ref := filepath.Join(dir, phase+".json")
				if e = os.WriteFile(ref, data, 0600); e != nil {
					t.Fatal(e)
				}
				command := exec.CommandContext(f.f.ctx, "python3", filepath.Join("..", "..", "scripts", "lftp-probe.py"), "--reference", ref)
				out, e := command.CombinedOutput()
				if e != nil {
					t.Fatalf("stock lftp ticket probe failed: %v; %s", e, out)
				}
				var report struct {
					State  string
					Cases  int    `json:"case_count"`
					Stock  bool   `json:"stock_client_qualification"`
					SHA256 string `json:"payload_sha256"`
				}
				if e = json.Unmarshal(out, &report); e != nil || report.State != "passed" || report.Cases != cases || !report.Stock || report.SHA256 != secure.Digest(payload) {
					t.Fatal("stock ticket proof incomplete", e)
				}
				if phase == "download" {
					actual, e := os.ReadFile(filepath.Join(dir, "download.lftp", "ticket.download"))
					if e != nil || !bytes.Equal(actual, payload) {
						t.Fatal("original stock client download bytes differ", e)
					}
				}
			}
			probe("resume", 2)
			completed, err := f.f.service.UploadStatus(f.f.ctx, f.f.a, created.Upload.ID)
			if err != nil || completed.State != "completed" || completed.Offset != int64(len(payload)) || completed.Acceptance != "durable-held-pending-checks-and-release" {
				t.Fatal("stock resume did not recover exact held acceptance", err)
			}
			if _, err = f.f.service.StatPath(f.f.ctx, f.f.a, "/stock-ticket.csv"); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("stock upload bypassed intake hold", err)
			}
			if _, err = s.Run(f.f.ctx, f.f.a, completed.FileID, "stock-ticket-check"); err != nil {
				t.Fatal(err)
			}
			view, err := s.Get(f.f.ctx, f.f.a, completed.FileID)
			if err != nil || view.Check.State != "passed" {
				t.Fatal("stock ticket check failed", err)
			}
			if _, err = s.Release(f.f.ctx, f.f.a, completed.FileID, "stock-ticket-release", checks.ReleaseDecision{SHA256: secure.Digest(payload), PolicyHash: view.Check.PolicyHash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}); err != nil {
				t.Fatal(err)
			}
			probe("download", 1)
		})
	}
}
