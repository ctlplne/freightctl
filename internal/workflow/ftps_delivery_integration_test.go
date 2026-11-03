//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/ftpsd"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

// The receiver is an actual separate freightctl custody/FTPS service on real
// PostgreSQL/storage, explicitly an application stand-in rather than a vendor
// peer. The wrapper drops one encrypted CONTROL reply after an independently
// observed durable receiver effect. Data sockets and TLS policy stay unchanged.
type replyLossListener struct {
	net.Listener
	after atomic.Pointer[replyLossHook]
	fired atomic.Bool
}
type replyLossHook struct{ after func() bool }

func (l *replyLossListener) setAfter(f func() bool) { l.after.Store(&replyLossHook{after: f}) }

type replyLossConn struct {
	net.Conn
	owner *replyLossListener
}

func (l *replyLossListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &replyLossConn{Conn: c, owner: l}, nil
}
func (c *replyLossConn) Write(b []byte) (int, error) {
	hook := c.owner.after.Load()
	if !c.owner.fired.Load() && hook != nil && hook.after() && c.owner.fired.CompareAndSwap(false, true) {
		c.Conn.Close()
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(b)
}

func governedFTPSReceiver(t *testing.T, implicit bool) (*fixture, delivery.FTPSDefinition, *replyLossListener) {
	t.Helper()
	r := setup(t)
	r.s.Custody.NamespaceMaxEntries = 100
	for _, dir := range []string{"/stage", "/inbox"} {
		if _, err := r.s.Custody.PathCommand(r.ctx, r.scope, "receiver-"+strings.TrimPrefix(dir, "/"), store.PathCommand{Operation: "mkdir", Path: dir}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "receiver.pem"), filepath.Join(dir, "receiver.key")
	if err := secure.DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	identity, err := secure.LoadFTPSIdentity(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ftpsd.New(r.s.Custody, ftpsd.Options{Identity: identity, Implicit: implicit, MaxConnections: 4, MaxWriters: 1, ListLimit: 100, SessionLimit: 30 * time.Second, IdleLimit: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	loss := &replyLossListener{Listener: l}
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, loss) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("receiver did not join its owned sockets")
		}
	})
	ca, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	password, err := secure.ReadSecret(r.tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash := secure.Digest(password.Bytes)
	password.Close()
	mode := "explicit"
	if implicit {
		mode = "implicit"
	}
	return r, delivery.FTPSDefinition{Destination: secure.FTPSDestination{Address: l.Addr().String(), ServerName: "localhost", Mode: mode, User: r.scope.Tenant + "/" + r.scope.Partner, CAFile: cert, CASHA256: secure.Digest(ca), PasswordFile: r.tokenPath, PasswordSHA256: passwordHash}, StagingDirectory: "/stage", ReceiverContract: store.FTPSReceiverContract{Schema: 1, DocumentSHA256: secure.Digest([]byte("test-only receiver-private stage, may-replace rename, receiver deduplication assertion, exact-readback receipt")), StagingVisibility: "receiver-private", Rename: "may-replace", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}, loss
}

func queueFTPS(t *testing.T, f *fixture, s *delivery.Service, spec delivery.FTPSDefinition) (*store.Delivery, delivery.Request) {
	t.Helper()
	r := delivery.Request{FileID: f.file.ID, Directory: "/inbox", Filename: "payroll.csv", FTPS: &spec}
	created, err := s.Create(f.ctx, f.scope, "ftps-create", r)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Create(f.ctx, f.scope, "ftps-create", r)
	if err != nil || !again.Replayed || again.Delivery.ID != created.Delivery.ID {
		t.Fatal("draft receipt changed", err)
	}
	queued, err := s.Command(f.ctx, f.scope, created.Delivery.ID, "ftps-queue", "approve", created.Delivery.DefinitionHash, created.Delivery.Revision)
	if err != nil {
		t.Fatal(err)
	}
	return queued.Delivery, r
}

func readReceiverBytes(t *testing.T, r *fixture, name string) []byte {
	t.Helper()
	_, file, err := r.s.Custody.DownloadPath(r.ctx, r.scope, name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, 4))
	if err != nil || !bytes.Equal(b, []byte("abc")) {
		t.Fatal("independent receiver bytes differ", err)
	}
	return b
}

func approveFTPS(t *testing.T, f *fixture, s *delivery.Service, d *store.Delivery, reviewer store.Scope, account store.AccountCommand) store.OutboundDispatchSummary {
	t.Helper()
	p, r, _ := proposeDispatch(t, f, s, d, account.ID, "ftps-review")
	data, _ := json.Marshal(p)
	var spec delivery.Definition
	if json.Unmarshal(d.Definition, &spec) != nil {
		t.Fatal("definition")
	}
	for _, secret := range []string{spec.FTPS.Destination.CAFile, spec.FTPS.Destination.PasswordFile, spec.FTPS.Destination.PasswordSHA256} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("review disclosed protected reference or password digest")
		}
	}
	if p.Definition.Schema != 2 || p.Definition.Effect.Protocol != "ftps" || p.Definition.Effect.FTPS == nil {
		t.Fatal("wrong approved protocol")
	}
	r, _, err := decideDispatch(t, f, s, reviewer, r, "approve", "ftps-consent")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGovernedFTPSActualServiceStandInRequiresIndependentApprovalAndExactReadback(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		mode := "explicit"
		if implicit {
			mode = "implicit"
		}
		t.Run(mode, func(t *testing.T) {
			f, s, reviewer, account := outboundFixture(t)
			r, spec, _ := governedFTPSReceiver(t, implicit)
			d, request := queueFTPS(t, f, s, spec)
			if _, err := s.Work(f.ctx, f.scope, d.ID); !errors.Is(err, store.ErrDispatchApproval) {
				t.Fatal("worker bypassed independent approval", err)
			}
			request.FTPS.ReceiverContract.DocumentSHA256 = strings.Repeat("d", 64)
			if _, err := s.Create(f.ctx, f.scope, "ftps-create", request); !errors.Is(err, store.ErrConflict) {
				t.Fatal("receiver contract changed under old receipt", err)
			}
			approveFTPS(t, f, s, d, reviewer, account)
			completed, err := s.Work(f.ctx, f.scope, d.ID)
			if err != nil || completed.State != "succeeded" || completed.Attempts != 1 || completed.Fence != 1 {
				t.Fatal("governed transfer", completed, err)
			}
			readReceiverBytes(t, r, "/inbox/"+d.ID+"-payroll.csv")
			var observed map[string]any
			json.Unmarshal(completed.Observation, &observed)
			if observed["protocol"] != "ftps" || observed["file_fsync_acknowledged"] != false || observed["rename_acknowledged"] != true || observed["business_acceptance"] != "unknown" {
				t.Fatal("inflated receipt", observed)
			}
		})
	}
}

func TestGovernedFTPSLostActualCompletionNeverResendsAndReconcilesReadOnly(t *testing.T) {
	for _, phase := range []string{"stage", "rename"} {
		t.Run(phase, func(t *testing.T) {
			f, s, reviewer, account := outboundFixture(t)
			r, spec, loss := governedFTPSReceiver(t, false)
			d, _ := queueFTPS(t, f, s, spec)
			approveFTPS(t, f, s, d, reviewer, account)
			stage := "/stage/.freightctl-" + d.ID + ".partial"
			final := "/inbox/" + d.ID + "-payroll.csv"
			cut := stage
			if phase == "rename" {
				cut = final
			}
			loss.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, cut); return err == nil })
			out, err := s.Work(f.ctx, f.scope, d.ID)
			if err != nil || out.State != "ambiguous" || !loss.fired.Load() {
				t.Fatal("lost reply not retained", out, err)
			}
			var events int64
			if err = r.admin.QueryRow(r.ctx, `SELECT count(*) FROM events`).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Work(f.ctx, f.scope, d.ID); !errors.Is(err, store.ErrState) {
				t.Fatal("uncertain payload automatically retried", err)
			}
			reconciled, err := s.Reconcile(f.ctx, f.scope, d.ID)
			if err != nil || reconciled.Attempts != out.Attempts || reconciled.Fence != out.Fence {
				t.Fatal("read-only recovery changed sending identity", err)
			}
			if phase == "stage" {
				if reconciled.State != "ambiguous" {
					t.Fatal("missing final invented publication")
				}
				readReceiverBytes(t, r, stage)
			} else {
				if reconciled.State != "succeeded" {
					t.Fatal("exact final not observed")
				}
				readReceiverBytes(t, r, final)
				var receipt map[string]any
				json.Unmarshal(reconciled.Observation, &receipt)
				if receipt["rename_acknowledged"] != false || receipt["file_fsync_acknowledged"] != false || receipt["reconciled"] != true {
					t.Fatal("readback invented lost reply")
				}
			}
			var after int64
			if err = r.admin.QueryRow(r.ctx, `SELECT count(*) FROM events`).Scan(&after); err != nil || after != events {
				t.Fatal("recovery mutated receiver", events, after, err)
			}
		})
	}
}

func TestGovernedFTPSWithdrawnConsentAfterStagePreventsRename(t *testing.T) {
	f, s, reviewer, account := outboundFixture(t)
	r, spec, loss := governedFTPSReceiver(t, false)
	d, _ := queueFTPS(t, f, s, spec)
	consent := approveFTPS(t, f, s, d, reviewer, account)
	stage := "/stage/.freightctl-" + d.ID + ".partial"
	var withdrawn atomic.Bool
	withdrawal := make(chan error, 1)
	loss.setAfter(func() bool {
		if !withdrawn.Load() {
			if _, err := r.s.Custody.StatPath(r.ctx, r.scope, stage); err == nil {
				if withdrawn.CompareAndSwap(false, true) {
					_, err = s.DecideDispatchReview(f.ctx, reviewer, consent.ID, "withdraw", "withdraw-during-stage", delivery.DispatchDecision{Hash: consent.Hash, Revision: consent.Revision})
					withdrawal <- err
				}
			}
		}
		return false
	})
	out, err := s.Work(f.ctx, f.scope, d.ID)
	if err != nil || !withdrawn.Load() || out.State != "ambiguous" {
		t.Fatal("live withdrawal bypassed", out, err)
	}
	select {
	case withdrawalErr := <-withdrawal:
		if withdrawalErr != nil {
			t.Fatal(withdrawalErr)
		}
	case <-time.After(time.Second):
		t.Fatal("withdrawal did not complete")
	}
	if _, err = r.s.Custody.StatPath(r.ctx, r.scope, "/inbox/"+d.ID+"-payroll.csv"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoked intent renamed", err)
	}
	readReceiverBytes(t, r, stage)
}

func TestGovernedFTPSSQLRefusesChangedReceiverEffectsAndUnapprovedStaging(t *testing.T) {
	f, s, _, account := outboundFixture(t)
	_, spec, _ := governedFTPSReceiver(t, false)
	d, _ := queueFTPS(t, f, s, spec)
	selection := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: account.ID}
	preview, err := s.PreviewDispatchReview(f.ctx, f.scope, selection)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*store.OutboundDispatchDefinition){
		func(x *store.OutboundDispatchDefinition) { x.Effect.FTPS.Mode = "implicit" },
		func(x *store.OutboundDispatchDefinition) {
			x.Effect.FTPS.ReceiverContract.DocumentSHA256 = strings.Repeat("d", 64)
		},
		func(x *store.OutboundDispatchDefinition) { x.Effect.FTPS.StagingPath = "/inbox/visible.partial" },
		func(x *store.OutboundDispatchDefinition) { x.Schema = 1 },
	} {
		encoded, _ := json.Marshal(preview.Definition)
		var altered store.OutboundDispatchDefinition
		json.Unmarshal(encoded, &altered)
		change(&altered)
		encoded, _ = json.Marshal(altered)
		tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		now, err := tx.DatabaseTime(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		review := &store.OutboundDispatchReview{OutboundDispatchSummary: store.OutboundDispatchSummary{ID: secure.NewID(), Author: altered.Author, Reviewer: altered.Reviewer, DeliveryID: d.ID, Hash: secure.Digest(encoded), State: "pending", Revision: 1, CreatedAt: now}, Definition: altered}
		err = tx.SaveOutboundDispatchReview(f.ctx, review, 0)
		tx.Tx.Rollback(f.ctx)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" || (pe.Message != "dispatch effects must equal exact intent" && pe.Message != "dispatch schema must equal exact intent") {
			t.Fatal("SQL accepted changed effect or failed unrelated check", err)
		}
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	row, err := tx.Delivery(f.ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(30 * time.Second)
	row.State = "staging"
	row.Revision++
	row.Fence++
	row.Attempts++
	row.LeaseOwner = secure.NewID()
	row.LeaseUntil = &until
	err = tx.SaveDelivery(f.ctx, row, d.Revision)
	tx.Tx.Rollback(f.ctx)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.Message != "current outbound dispatch approval required" {
		t.Fatal("SQL staging bypassed named consent", err)
	}
}
