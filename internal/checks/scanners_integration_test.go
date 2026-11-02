//go:build integration

package checks

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

// The scanner peer is a contract fixture. PostgreSQL, custody and authority are
// real; no test here qualifies ClamAV, vendor definitions or malware detection.
func scanFixture(t *testing.T, mode string, valid time.Duration) (*fixture, *Service, *ScannerView, *store.File, scanner.Definition) {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	dir, err := os.MkdirTemp("", "freightctl-scan-pg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, name := range []string{"db", "tmp"} {
		if err = os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	definition := scanner.Definition{Schema: 1, Kind: scanner.Backend, Socket: filepath.Join(dir, "s"), Configuration: filepath.Join(dir, "clamd.conf"), ExpectedVersion: "ClamAV 1.5.4/30001/" + now.Add(-time.Hour).Format("Mon Jan _2 15:04:05 2006"), ValidUntil: now.Add(valid), MaxBytes: 8 << 20, TimeoutSeconds: 2, MaxResultAgeSeconds: 600}
	if mode == "precision" {
		definition.ValidUntil = now.Add(valid).Truncate(time.Second).Add(123456789 * time.Nanosecond)
	}
	config := fmt.Sprintf("Foreground yes\nLocalSocket %s\nLocalSocketMode 600\nDatabaseDirectory %s\nTemporaryDirectory %s\nMaxThreads 1\nMaxQueue 2\nStreamMaxLength 8388608\nMaxFileSize 8388608\nMaxScanSize 16777216\nMaxRecursion 4\nMaxFiles 100\nMaxScanTime 1000\nReadTimeout 2\nCommandReadTimeout 2\nSendBufTimeout 1000\nScanArchive yes\nAlertExceedsMax yes\nAlertEncrypted yes\nOfficialDatabaseOnly yes\nBytecode yes\nBytecodeSecurity TrustSigned\nConcurrentDatabaseReload no\nSelfCheck 0\nEnableVersionCommand yes\nEnableReloadCommand no\nEnableShutdownCommand no\nEnableStatsCommand no\n", definition.Socket, filepath.Join(dir, "db"), filepath.Join(dir, "tmp"))
	if err = os.WriteFile(definition.Configuration, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	definition.ConfigurationSHA256 = secure.Digest([]byte(config))
	registered, err := s.RegisterScanner(f.ctx, f.scope, "scanner", ScannerRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var view ScannerView
	if json.Unmarshal(registered.Resource, &view) != nil {
		t.Fatal("scanner result")
	}
	if replay, err := s.RegisterScanner(f.ctx, f.scope, "scanner", ScannerRequest{Definition: definition}); err != nil || !replay.Replayed {
		t.Fatal(replay, err)
	}
	policy := testPolicy(t)
	policy.Scanner = &store.ScannerReference{ID: view.ID, Version: view.Version, Hash: view.Hash}
	if _, err = s.Register(f.ctx, f.scope, "policy", PolicyRequest{Definition: policy}); err != nil {
		t.Fatal(err)
	}
	body := goodCSV
	if mode == "detected_before_csv" {
		body = "not a valid CSV contract"
	}
	file, _, err := f.wf.Custody.AcceptAt(f.ctx, f.scope, "held", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body), custody.UploadTarget{Path: "/scanned.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if mode != "offline" {
		listener, err := net.Listen("unix", definition.Socket)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.Chmod(definition.Socket, 0600); err != nil {
			t.Fatal(err)
		}
		done := make(chan struct{})
		t.Cleanup(func() { _ = listener.Close(); <-done })
		go func() {
			defer close(done)
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					r := bufio.NewReader(c)
					cmd := func(want string) bool { v, e := r.ReadString(0); return e == nil && v == want+"\x00" }
					if !cmd("zIDSESSION") || !cmd("zVERSION") {
						return
					}
					_, _ = io.WriteString(c, "1: "+definition.ExpectedVersion+"\x00")
					if !cmd("zINSTREAM") {
						return
					}
					var header [4]byte
					for {
						if _, err := io.ReadFull(r, header[:]); err != nil {
							return
						}
						n := binary.BigEndian.Uint32(header[:])
						if n == 0 {
							break
						}
						if n > 32<<10 {
							return
						}
						if _, err = io.CopyN(io.Discard, r, int64(n)); err != nil {
							return
						}
					}
					reply := "2: stream: OK"
					if mode == "detected_before_csv" {
						reply = "2: stream: Unit.Contract.Detection FOUND"
					}
					if mode == "blocked" {
						reply = "2: stream: Heuristics.Limits.Exceeded.MaxFiles FOUND"
					}
					if mode == "malformed" {
						reply = "2: stream: OK extra"
					}
					_, _ = io.WriteString(c, reply+"\x00")
					if !cmd("zVERSION") {
						return
					}
					_, _ = io.WriteString(c, "3: "+definition.ExpectedVersion+"\x00")
					_ = cmd("zEND")
				}()
			}
		}()
	}
	return f, s, &view, file, definition
}
func TestScannerGateStoresExactProofThenRequiresReleaseAndCurrentProfile(t *testing.T) {
	f, s, profile, file, _ := scanFixture(t, "clean", time.Hour)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	var report Report
	if json.Unmarshal(c.Report, &report) != nil || c.State != "passed" || report.Scanner == nil || report.Scanner.Result.Verdict != "clean" || report.Scanner.Result.SHA256 != file.SHA256 {
		t.Fatal(c)
	}
	if _, _, err := s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("scan bypassed approval", err)
	}
	if _, err := s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c)); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.OpenPathReader(f.ctx, f.scope, "/scanned.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if _, err = reader.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeScanner(f.ctx, f.scope, profile.ID, profile.Version, "revoke-scanner", workflow.Decision{Hash: profile.Hash, Revision: profile.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ReadAt(make([]byte, 1), 1); !errors.Is(err, store.ErrState) {
		t.Fatal("open reader ignored scanner revocation", err)
	}
	if view, err := s.Get(f.ctx, f.scope, file.ID); err != nil || view.Current {
		t.Fatal(view, err)
	}
}
func TestUnavailableMalformedAndDetectedScansNeverBecomeClean(t *testing.T) {
	for _, mode := range []string{"offline", "malformed", "blocked", "detected_before_csv"} {
		t.Run(mode, func(t *testing.T) {
			f, s, _, file, _ := scanFixture(t, mode, time.Hour)
			if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
				t.Fatal(err)
			}
			c := getCheck(t, s, f, file.ID)
			if mode == "offline" || mode == "malformed" {
				if c.State != "failed" || c.Code != "scanner_unavailable" || c.ReportHash != "" {
					t.Fatal(c)
				}
			} else {
				if c.State != "rejected" || c.Code != (map[string]string{"blocked": "scanner_blocked", "detected_before_csv": "scanner_detected"})[mode] {
					t.Fatal(c)
				}
			}
			if _, _, err := s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
				t.Fatal("non-clean scan exposed bytes", err)
			}
		})
	}
}
func TestScanSQLRequiresProofAndProfileMaterialIsImmutable(t *testing.T) {
	f, s, profile, file, _ := scanFixture(t, "offline", time.Hour)
	c, b, policy, _, _, err := s.start(f.ctx, f.scope, file.ID, "start")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Validate(f.ctx, policy, b.File, c.PolicyHash, strings.NewReader(goodCSV))
	if err != nil {
		t.Fatal(err)
	}
	c.Report, c.ReportHash, err = canonical(report)
	if err != nil {
		t.Fatal(err)
	}
	previous := c.Revision
	c.Revision++
	c.State = "passed"
	c.Code = "valid_csv"
	c.WorkerID = ""
	c.LeaseUntil = nil
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.SaveFileCheck(f.ctx, c, previous); err == nil || !strings.Contains(err.Error(), "passing scan verdict requires") {
		t.Fatal("missing scanner proof accepted", err)
	}
	_ = tx.Tx.Rollback(f.ctx)
	tx, err = s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	p, err := tx.ScannerProfile(f.ctx, profile.ID, profile.Version, true)
	if err != nil {
		t.Fatal(err)
	}
	previous = p.Revision
	p.Revision++
	p.State = "revoked"
	p.Definition = json.RawMessage(`{}`)
	if err = tx.SaveScannerProfile(f.ctx, p, previous); err == nil {
		t.Fatal("scanner material changed")
	}
	_ = tx.Tx.Rollback(f.ctx)
}
func TestScanProofExpiryStopsReleasedReads(t *testing.T) {
	f, s, _, file, _ := scanFixture(t, "clean", 2*time.Second)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	if _, err := s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(c)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, _, err := s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("expired proof exposed bytes", err)
	}
}
func TestScannerSlotsRemainSeparateFromDelivery(t *testing.T) {
	f := setup(t)
	_, a, err := f.wf.Custody.DB.ScanWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	_, b, err := f.wf.Custody.DB.ScanWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	if _, release, err := f.wf.Custody.DB.ScanWorkerSlot(f.ctx); !errors.Is(err, store.ErrLimit) {
		if release != nil {
			release()
		}
		t.Fatal("scan admission unbounded", err)
	}
	_, delivery, err := f.wf.Custody.DB.DeliveryWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal("scanning consumed transfer slots", err)
	}
	delivery()
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, _, err = f.wf.Custody.DB.ScanWorkerSlot(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestScannerExpiryRoundTripsThroughPostgreSQLPrecision(t *testing.T) {
	f, s, _, file, _ := scanFixture(t, "precision", time.Hour)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
		t.Fatal(err)
	}
	if c := getCheck(t, s, f, file.ID); c.State != "passed" {
		t.Fatal(c)
	}
}

func TestScannerAuthorityIsolationAndReceiptRollback(t *testing.T) {
	f, s, profile, file, definition := scanFixture(t, "offline", time.Hour)
	makeScope := func(tenant string, permissions []string) store.Scope {
		t.Helper()
		token := filepath.Join(t.TempDir(), "token")
		if err := secure.WriteToken(token); err != nil {
			t.Fatal(err)
		}
		if err := store.ProvisionPolicy(f.ctx, f.adminPath, tenant, f.scope.Partner, token, permissions, "/"); err != nil {
			t.Fatal(err)
		}
		secret, err := secure.ReadSecret(token, 64)
		if err != nil {
			t.Fatal(err)
		}
		scope := store.Scope{Tenant: tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		return scope
	}
	old := []string{}
	for _, grant := range store.DefaultPermissions {
		if grant != "scanner_manage" {
			old = append(old, grant)
		}
	}
	other := makeScope(f.scope.Tenant, old)
	if _, err := s.RegisterScanner(f.ctx, other, "no-scan-grant", ScannerRequest{Definition: definition}); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("implicit scanner grant", err)
	}
	if _, err := s.Get(f.ctx, other, file.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("private check disclosed", err)
	}
	foreign := makeScope(secure.NewID(), store.DefaultPermissions)
	if _, err := s.Scanner(f.ctx, foreign, profile.ID, profile.Version); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("foreign profile disclosed", err)
	}
	view, err := s.Scanner(f.ctx, f.scope, profile.ID, profile.Version)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(view)
	if strings.Contains(string(encoded), definition.Socket) || strings.Contains(string(encoded), definition.Configuration) {
		t.Fatal("local references escaped sanitized view")
	}
	if _, err = f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_scanner_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.result ? 'expected_engine' THEN RAISE EXCEPTION 'task-owned scanner receipt failure';END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_test_scanner_receipt_failure BEFORE INSERT ON check_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_scanner_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterScanner(f.ctx, f.scope, "failed-enrollment", ScannerRequest{Definition: definition}); err == nil {
		t.Fatal("scanner enrollment survived failed receipt")
	}
	var n int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM scanner_profiles`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='ScannerProfileChanged'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("profile event escaped rollback", n, err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER freightctl_test_scanner_receipt_failure ON check_receipts;DROP FUNCTION freightctl_test_scanner_receipt_failure()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterScanner(f.ctx, f.scope, "failed-enrollment", ScannerRequest{Definition: definition}); err != nil {
		t.Fatal("original enrollment could not retry", err)
	}
}
func TestChangedScannerConfigurationCannotApproveRelease(t *testing.T) {
	f, s, _, file, definition := scanFixture(t, "clean", time.Hour)
	if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	config, err := os.OpenFile(definition.Configuration, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = config.WriteString("# changed after scan\n")
	_ = config.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "changed-config", releaseDecision(c)); !errors.Is(err, store.ErrState) {
		t.Fatal("changed configuration approval accepted", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("changed scan context exposed bytes", err)
	}
}

func TestReleasedScannerConfigurationIsRecheckedForNewAndOpenReaders(t *testing.T) {
	for _, change := range []string{"content", "permissions", "missing"} {
		t.Run(change, func(t *testing.T) {
			f, s, _, file, definition := scanFixture(t, "clean", time.Hour)
			if _, err := s.Run(f.ctx, f.scope, file.ID, "scan"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Release(f.ctx, f.scope, file.ID, "release", releaseDecision(getCheck(t, s, f, file.ID))); err != nil {
				t.Fatal(err)
			}
			_, reader, err := s.Custody.OpenPathReader(f.ctx, f.scope, "/scanned.csv")
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if n, err := reader.ReadAt(make([]byte, 1), 0); err != nil || n != 1 {
				t.Fatal("valid proof unreadable", n, err)
			}
			original, err := os.ReadFile(definition.Configuration)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "content":
				err = os.WriteFile(definition.Configuration, append(append([]byte{}, original...), []byte("# changed after release\n")...), 0600)
			case "permissions":
				err = os.Chmod(definition.Configuration, 0644)
			case "missing":
				err = os.Remove(definition.Configuration)
			}
			if err != nil {
				t.Fatal(err)
			}
			if n, err := reader.ReadAt(make([]byte, 1), 1); !errors.Is(err, store.ErrState) || n != 0 {
				t.Fatal("open reader accepted changed scanner configuration", n, err)
			}
			if _, data, err := s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
				if data != nil {
					_ = data.Close()
				}
				t.Fatal("new ID read accepted changed scanner configuration", err)
			}
			if _, data, err := s.Custody.DownloadPath(f.ctx, f.scope, "/scanned.csv"); !errors.Is(err, store.ErrState) {
				if data != nil {
					_ = data.Close()
				}
				t.Fatal("new path read accepted changed scanner configuration", err)
			}
			if err := os.WriteFile(definition.Configuration, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(definition.Configuration, 0600); err != nil {
				t.Fatal(err)
			}
			if n, err := reader.ReadAt(make([]byte, 1), 1); err != nil || n != 1 {
				t.Fatal("restored exact proof unreadable", n, err)
			}
		})
	}
}
