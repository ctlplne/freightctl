//go:build integration

package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/ctlplne/freightctl/internal/workflow"
)

type intakeFTPSListener struct {
	net.Listener
	contacts atomic.Int64
}

func (l *intakeFTPSListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err == nil {
		l.contacts.Add(1)
	}
	return connection, err
}

func intakeFTPSReceiver(t *testing.T, mode string) (*fixture, delivery.FTPSDefinition, *intakeFTPSListener) {
	t.Helper()
	r := setup(t)
	for _, directory := range []string{"/stage", "/inbox"} {
		if _, err := r.wf.Custody.PathCommand(r.ctx, r.scope, "receiver-"+strings.TrimPrefix(directory, "/"), store.PathCommand{Operation: "mkdir", Path: directory}); err != nil {
			t.Fatal(err)
		}
	}
	directory := t.TempDir()
	certificate, key := filepath.Join(directory, "receiver.pem"), filepath.Join(directory, "receiver.key")
	if err := secure.DevCertificate(certificate, key); err != nil {
		t.Fatal(err)
	}
	identity, err := secure.LoadFTPSIdentity(certificate, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ftpsd.New(r.wf.Custody, ftpsd.Options{Identity: identity, Implicit: mode == "implicit", MaxConnections: 4, MaxWriters: 1, ListLimit: 100, SessionLimit: 30 * time.Second, IdleLimit: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &intakeFTPSListener{Listener: socket}
	ctx, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("intake FTPS receiver did not join its owned sockets")
		}
	})
	ca, err := os.ReadFile(certificate)
	if err != nil {
		t.Fatal(err)
	}
	password, err := secure.ReadSecret(r.tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	proof := secure.Digest(password.Bytes)
	password.Close()
	return r, delivery.FTPSDefinition{Destination: secure.FTPSDestination{Address: listener.Addr().String(), ServerName: "localhost", Mode: mode, User: r.scope.Tenant + "/" + r.scope.Partner, CAFile: certificate, CASHA256: secure.Digest(ca), PasswordFile: r.tokenPath, PasswordSHA256: proof}, StagingDirectory: "/stage", ReceiverContract: store.FTPSReceiverContract{Schema: 1, DocumentSHA256: secure.Digest([]byte("intake test-only receiver-private staging and exact readback; not business acceptance")), StagingVisibility: "receiver-private", Rename: "may-replace", Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback"}}, listener
}

func TestRegisteredFTPSWorkflowRequiresExactIntakeReleaseAndCurrentPolicy(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		for _, schema := range []int{1, 2} {
			for _, revoke := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/schema%d/revoke=%t", mode, schema, revoke), func(t *testing.T) {
					f := setup(t)
					r, ftp, listener := intakeFTPSReceiver(t, mode)
					checks, policy, file := policyAndFile(t, f, goodCSV, true)
					sender := &delivery.Service{Custody: f.wf.Custody}
					if _, err := sender.ChangeDispatchPolicy(f.ctx, f.scope, "intake-dispatch-policy", delivery.DispatchPolicyChange{Mode: "independent"}); err != nil {
						t.Fatal(err)
					}
					registered, err := f.wf.RegisterConnection(f.ctx, f.scope, "intake-ftps-connection", workflow.ConnectionRequest{Directory: "/inbox", FTPS: &ftp})
					if err != nil {
						t.Fatal(err)
					}
					var connection workflow.ConnectionView
					if json.Unmarshal(registered.Resource, &connection) != nil {
						t.Fatal("registered connection")
					}
					definition := workflow.Definition{Schema: schema, Name: "Checked FTPS settlement", Steps: []workflow.Step{{ID: "send", Kind: "ftps.deliver", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Filename: "checked.csv"}}}
					if schema == 2 {
						definition.Program = &workflow.Program{Nodes: []workflow.ProgramNode{{Kind: "deliver", Step: "send"}}}
					}
					draft, err := f.wf.Draft(f.ctx, f.scope, "checked-draft", workflow.DraftRequest{Definition: definition})
					if err != nil {
						t.Fatal(err)
					}
					var config store.Configuration
					if json.Unmarshal(draft.Resource, &config) != nil {
						t.Fatal("workflow draft")
					}
					if _, err = f.wf.Decide(f.ctx, f.scope, config.ID, config.Version, "checked-approve", "approve", workflow.Decision{Hash: config.Hash, Revision: config.Revision}); err != nil {
						t.Fatal(err)
					}
					request := workflow.RunRequest{Workflow: workflow.Reference{ID: config.ID, Version: config.Version, Hash: config.Hash}, FileID: file.ID}
					requireHeld := func() {
						t.Helper()
						if _, err := f.wf.Validate(f.ctx, f.scope, workflow.PreviewRequest{Definition: definition, FileID: file.ID}); !errors.Is(err, store.ErrState) {
							t.Fatal("workflow preview bypassed exact intake release", err)
						}
						if _, err := f.wf.Run(f.ctx, f.scope, "checked-run", request); !errors.Is(err, store.ErrState) {
							t.Fatal("workflow approval bypassed held source", err)
						}
						var runs, intents int
						if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM delivery_intents)`).Scan(&runs, &intents); err != nil || runs != 0 || intents != 0 || listener.contacts.Load() != 0 {
							t.Fatal("held source admitted sending state or contacted receiver", err)
						}
					}
					requireHeld()
					if _, err = checks.Run(f.ctx, f.scope, file.ID, "checked-parse"); err != nil {
						t.Fatal(err)
					}
					check := getCheck(t, checks, f, file.ID)
					if check.State != "passed" || check.Attempts != 1 {
						t.Fatal("CSV check did not pass once")
					}
					requireHeld()
					wrong := releaseDecision(check)
					wrong.ReportHash = strings.Repeat("f", 64)
					if _, err = checks.Release(f.ctx, f.scope, file.ID, "wrong-checked-release", wrong); !errors.Is(err, store.ErrRevision) {
						t.Fatal("wrong check report authorized release", err)
					}
					requireHeld()
					if _, err = checks.Release(f.ctx, f.scope, file.ID, "checked-release", releaseDecision(check)); err != nil {
						t.Fatal(err)
					}
					started, err := f.wf.Run(f.ctx, f.scope, "checked-run", request)
					if err != nil {
						t.Fatal("released exact source was not admitted", err)
					}
					var run store.WorkflowRun
					if json.Unmarshal(started.Resource, &run) != nil || run.Source != *file {
						t.Fatal("run changed released source")
					}
					status, err := f.wf.Status(f.ctx, f.scope, run.ID)
					if err != nil || len(status.Steps) != 1 {
						t.Fatal("checked run intent", err)
					}
					id := status.Steps[0].DeliveryID
					if _, err = f.wf.Work(f.ctx, f.scope, run.ID, "checked-worker"); !errors.Is(err, store.ErrDispatchApproval) || listener.contacts.Load() != 0 {
						t.Fatal("intake release bypassed independent dispatch consent", err)
					}
					d, err := sender.Status(f.ctx, f.scope, id)
					if err != nil || d.Attempts != 0 || d.Fence != 0 {
						t.Fatal("refused checked source consumed sender identity", err)
					}
					reviewer := f.scope
					reviewer.TokenHash = secure.Digest([]byte(secure.NewID()))
					accountID := secure.NewID()
					if _, err = f.wf.Custody.DB.ChangeAccount(f.ctx, f.scope, "checked-reviewer", store.AccountCommand{Operation: "create", ID: accountID, CredentialHash: reviewer.TokenHash, Policy: &store.AccountPolicy{Label: "Checked FTPS reviewer", Root: "/", Permissions: []string{"inspect", "workflow_approve"}}}); err != nil {
						t.Fatal(err)
					}
					selection := delivery.DispatchSelection{DeliveryID: d.ID, DispatchDecision: delivery.DispatchDecision{Hash: d.DefinitionHash, Revision: d.Revision}, ReviewerID: accountID}
					preview, err := sender.PreviewDispatchReview(f.ctx, f.scope, selection)
					if err != nil || preview.Definition.Source != *file {
						t.Fatal("review lost the checked exact source", err)
					}
					proposal, err := sender.ProposeDispatchReview(f.ctx, f.scope, "checked-review", delivery.DispatchProposal{Selection: selection, Hash: preview.Hash})
					if err != nil {
						t.Fatal(err)
					}
					var review delivery.DispatchReviewResult
					if json.Unmarshal(proposal.Resource, &review) != nil {
						t.Fatal("dispatch proposal")
					}
					if _, err = sender.DecideDispatchReview(f.ctx, reviewer, review.Review.ID, "approve", "checked-consent", delivery.DispatchDecision{Hash: review.Review.Hash, Revision: review.Review.Revision}); err != nil {
						t.Fatal(err)
					}
					if revoke {
						var before, after []byte
						if err = f.admin.QueryRow(f.ctx, `SELECT to_jsonb(d) FROM delivery_intents d WHERE delivery_id=$1`, id).Scan(&before); err != nil {
							t.Fatal(err)
						}
						if _, err = checks.Revoke(f.ctx, f.scope, "revoke-checked-policy", PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
							t.Fatal(err)
						}
						if _, err = f.wf.Work(f.ctx, f.scope, run.ID, "checked-worker"); !errors.Is(err, store.ErrState) || listener.contacts.Load() != 0 {
							t.Fatal("saved consent bypassed revoked intake policy", err)
						}
						if err = f.admin.QueryRow(f.ctx, `SELECT to_jsonb(d) FROM delivery_intents d WHERE delivery_id=$1`, id).Scan(&after); err != nil || !bytes.Equal(before, after) {
							t.Fatal("revoked intake changed original intent/attempt/fence", err)
						}
						return
					}
					out, err := f.wf.Work(f.ctx, f.scope, run.ID, "checked-worker")
					if err != nil || !out.Replayed || out.Status.ObservedState != "succeeded" {
						t.Fatal("checked and independently approved FTPS workflow did not finish", err)
					}
					_, body, err := r.wf.Custody.DownloadPath(r.ctx, r.scope, "/inbox/"+id+"-checked.csv")
					if err != nil {
						t.Fatal(err)
					}
					actual, err := io.ReadAll(io.LimitReader(body, 1024))
					body.Close()
					if err != nil || !bytes.Equal(actual, []byte(goodCSV)) {
						t.Fatal("receiver bytes differ from checked source", err)
					}
					completed, err := sender.Status(f.ctx, f.scope, id)
					if err != nil || completed.Attempts != 1 || completed.Fence != 1 {
						t.Fatal("checked delivery did not retain its sending identity", err)
					}
					var receipt map[string]any
					if json.Unmarshal(completed.Observation, &receipt) != nil || receipt["sha256"] != file.SHA256 || receipt["size_bytes"] != float64(file.Size) || receipt["file_fsync_acknowledged"] != false || receipt["business_acceptance"] != "unknown" {
						t.Fatal("checked delivery receipt changed source or receiver promises")
					}
					contacts := listener.contacts.Load()
					replayed, err := f.wf.Work(f.ctx, f.scope, run.ID, "checked-worker")
					if err != nil || !replayed.Replayed || replayed.Dispatch != out.Dispatch || listener.contacts.Load() != contacts {
						t.Fatal("saved checked worker resent bytes", err)
					}
				})
			}
		}
	}
}
