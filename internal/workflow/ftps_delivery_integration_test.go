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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The receiver is an actual separate freightctl custody/FTPS service on real
// PostgreSQL/storage, explicitly an application stand-in rather than a vendor
// peer. The wrapper drops one encrypted CONTROL reply after an independently
// observed durable receiver effect. Data sockets and TLS policy stay unchanged.
type replyLossListener struct {
	net.Listener
	after    atomic.Pointer[replyLossHook]
	fired    atomic.Bool
	contacts atomic.Int64
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
	l.contacts.Add(1)
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

type receiverAuditEvent struct {
	kind, resource, actor, digest string
	payload                       map[string]any
}
type receiverReadSnapshot struct {
	tables map[string]string
	events map[string]receiverAuditEvent
}

// Compare every receiver table and every original event, while requiring the
// exact new read/session audit records. Audited reads must not be confused with
// payload mutation; dropping all audit checks would miss a hidden write.
func snapshotReceiverReads(t *testing.T, r *fixture) receiverReadSnapshot {
	t.Helper()
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(r.ctx)
	result := receiverReadSnapshot{tables: map[string]string{}, events: map[string]receiverAuditEvent{}}
	rows, err := tx.Query(r.ctx, `SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename<>'events' ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(tables) != 63 {
		t.Fatal("receiver table observation incomplete", len(tables), err)
	}
	for _, name := range tables {
		var raw []byte
		query := `SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM ` + pgx.Identifier{name}.Sanitize() + ` t`
		if err = tx.QueryRow(r.ctx, query).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		result.tables[name] = secure.Digest(raw)
		secure.Clear(raw)
	}
	rows, err = tx.Query(r.ctx, `SELECT event_id::text,kind,resource_id::text,actor_id::text,payload,to_jsonb(e) FROM events e ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var e receiverAuditEvent
		var raw, payload []byte
		if err = rows.Scan(&id, &e.kind, &e.resource, &e.actor, &payload, &raw); err != nil {
			t.Fatal(err)
		}
		e.digest = secure.Digest(raw)
		secure.Clear(raw)
		if json.Unmarshal(payload, &e.payload) != nil {
			t.Fatal("invalid receiver journal payload")
		}
		secure.Clear(payload)
		result.events[id] = e
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(r.ctx); err != nil {
		t.Fatal(err)
	}
	return result
}

func requireOnlyReceiverReadAudit(t *testing.T, r *fixture, before, after receiverReadSnapshot, fileID, phase, mode string) {
	t.Helper()
	if mode != "explicit" && mode != "implicit" {
		t.Fatal("unknown FTPS recovery audit profile")
	}
	if len(before.tables) != len(after.tables) {
		t.Fatal("receiver table set changed")
	}
	for name, digest := range before.tables {
		if after.tables[name] != digest {
			t.Fatal("read-only recovery changed receiver table", name)
		}
	}
	for id, event := range before.events {
		if after.events[id].digest != event.digest {
			t.Fatal("original receiver event changed or disappeared")
		}
	}
	identity, err := r.s.Custody.DB.Identity(r.ctx, r.scope)
	if err != nil {
		t.Fatal(err)
	}
	var session string
	var added []receiverAuditEvent
	for id, event := range after.events {
		if _, old := before.events[id]; old {
			continue
		}
		if event.actor != identity.Actor {
			t.Fatal("unexpected recovery audit actor")
		}
		added = append(added, event)
		if event.kind == "ProtocolSessionStarted" {
			if session != "" || !store.ValidID(event.resource) || len(event.payload) != 3 || event.payload["protocol"] != "ftps-"+mode || event.payload["tls_profile"] != "tls13-resumed-data-v1" || event.payload["authority_revision"] != float64(identity.AuthorityRevision) {
				t.Fatal("unexpected recovery protocol session")
			}
			session = event.resource
		}
	}
	wantDownloads := 1
	if phase == "rename" {
		wantDownloads = 2
	}
	if session == "" || len(added) != 1+wantDownloads {
		t.Fatal("unexpected receiver recovery audit count", len(added))
	}
	localReads, boundReads := 0, 0
	for _, event := range added {
		if event.kind == "ProtocolSessionStarted" {
			continue
		}
		if event.kind != "FileDownloadAuthorized" || event.resource != fileID || len(event.payload) != 2 || event.payload["sha256"] != secure.Digest([]byte("abc")) {
			t.Fatal("recovery added an unexpected receiver effect")
		}
		switch event.payload["protocol_session_id"] {
		case "":
			localReads++
		case session:
			boundReads++
		default:
			t.Fatal("read audit not bound to exact recovery session")
		}
	}
	if localReads != 1 || boundReads != wantDownloads-1 {
		t.Fatal("missing independent or protocol-bound read audit")
	}
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
			entry, err := r.s.Custody.StatPath(r.ctx, r.scope, cut)
			if err != nil {
				t.Fatal(err)
			}
			before := snapshotReceiverReads(t, r)
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
			requireOnlyReceiverReadAudit(t, r, before, snapshotReceiverReads(t, r), entry.FileID, phase, "explicit")
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
