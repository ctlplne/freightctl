//go:build integration

package workflow

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func registeredFTPSConnection(t *testing.T, f *fixture, spec delivery.FTPSDefinition) ConnectionView {
	t.Helper()
	return registeredFTPSConnectionForOperation(t, f, spec, "registered-ftps")
}

func registeredFTPSConnectionForOperation(t *testing.T, f *fixture, spec delivery.FTPSDefinition, key string) ConnectionView {
	t.Helper()
	request := ConnectionRequest{Directory: "/inbox", FTPS: &spec}
	first, err := f.s.RegisterConnection(f.ctx, f.scope, key, request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.RegisterConnection(f.ctx, f.scope, key, request)
	if err != nil || !again.Replayed {
		t.Fatal("connection receipt not recovered", err)
	}
	var original, replayed ConnectionView
	if json.Unmarshal(first.Resource, &original) != nil || json.Unmarshal(again.Resource, &replayed) != nil || !reflect.DeepEqual(original, replayed) {
		t.Fatal("connection replay changed the exact version")
	}
	view, err := f.s.Connection(f.ctx, f.scope, original.ID, original.Version)
	if err != nil || !reflect.DeepEqual(*view, original) || view.Protocol != "ftps" || view.FTPS == nil {
		t.Fatal("registered connection view differs", err)
	}
	for _, secret := range []string{spec.Destination.CAFile, spec.Destination.PasswordFile, spec.Destination.PasswordSHA256} {
		if strings.Contains(string(first.Resource), secret) {
			t.Fatal("connection exposed a protected reference or password proof")
		}
	}
	return original
}

func registeredFTPSRun(t *testing.T, f *fixture, s *delivery.Service, c ConnectionView, program bool) (*store.WorkflowRun, *store.Delivery) {
	t.Helper()
	definition := Definition{Schema: 1, Name: "Registered FTPS settlement", Steps: []Step{{ID: "send", Kind: "ftps.deliver", Connection: Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}, Filename: "payroll.csv"}}}
	if program {
		definition.Schema = 2
		definition.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: "send"}}}
	}
	preview, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: definition, FileID: f.file.ID})
	if err != nil || preview.ExternalContact || len(preview.Effects) != 1 || preview.Effects[0].Protocol != "ftps" || preview.Effects[0].FTPS == nil {
		t.Fatal("wrong typed FTPS preview", err)
	}
	wf := f.approved(t, definition)
	request := RunRequest{Workflow: Reference{ID: wf.ID, Version: wf.Version, Hash: wf.Hash}, FileID: f.file.ID}
	first, err := f.s.Run(f.ctx, f.scope, "registered-ftps-run", request)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.s.Run(f.ctx, f.scope, "registered-ftps-run", request)
	if err != nil || !again.Replayed {
		t.Fatal("workflow receipt not recovered", err)
	}
	var run, replay store.WorkflowRun
	if json.Unmarshal(first.Resource, &run) != nil || json.Unmarshal(again.Resource, &replay) != nil {
		t.Fatal("run receipt could not be decoded")
	}
	canonicalRun, err := canonicalWorkflowRunReceipt(run)
	if err != nil {
		t.Fatal("original run plan/hash binding differs", err)
	}
	canonicalReplay, err := canonicalWorkflowRunReceipt(replay)
	if err != nil {
		t.Fatal("replayed run plan/hash binding differs", err)
	}
	if !reflect.DeepEqual(canonicalRun, canonicalReplay) {
		t.Fatal("run replay changed intents")
	}
	if !reflect.DeepEqual(run, replay) {
		t.Log("run receipt JSON formatting differs; canonical plan/hash and every run field are equal")
	}
	status, err := f.s.Status(f.ctx, f.scope, run.ID)
	if err != nil || len(status.Steps) != 1 {
		t.Fatal("bound workflow step missing", err)
	}
	d, err := s.Status(f.ctx, f.scope, status.Steps[0].DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	var spec delivery.Definition
	if json.Unmarshal(d.Definition, &spec) != nil || spec.Schema != 2 || spec.FTPS == nil || spec.Binding == nil || spec.Binding.RunID != run.ID || spec.Binding.StepID != "send" || spec.Binding.ConnectionID != c.ID || spec.Binding.ConnectionVersion != c.Version || spec.Binding.ConnectionHash != c.Hash || spec.Binding.WorkflowHash != wf.Hash || spec.Source != *f.file {
		t.Fatal("delivery did not freeze its exact protocol/source/connection/run")
	}
	return &run, d
}

func requireUntouchedFTPSWorkflow(t *testing.T, f *fixture, s *delivery.Service, d *store.Delivery, listener *replyLossListener, contacts int64) {
	t.Helper()
	current, err := s.Status(f.ctx, f.scope, d.ID)
	if err != nil || !reflect.DeepEqual(current, d) || current.Attempts != 0 || current.Fence != 0 || listener.contacts.Load() != contacts {
		t.Fatal("refused work changed intent or contacted receiver", err)
	}
}

func TestRegisteredFTPSWorkflowRequiresIndependentConsentAndExactReceiverBytes(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		mode := "explicit"
		if implicit {
			mode = "implicit"
		}
		t.Run(mode, func(t *testing.T) {
			f, s, reviewer, account := outboundFixture(t)
			r, spec, listener := governedFTPSReceiver(t, implicit)
			c := registeredFTPSConnection(t, f, spec)
			run, d := registeredFTPSRun(t, f, s, c, false)
			contacts := listener.contacts.Load()
			if contacts != 0 {
				t.Fatal("registration or preview contacted receiver")
			}
			if _, err := f.s.Work(f.ctx, f.scope, run.ID, "worker"); !errors.Is(err, store.ErrDispatchApproval) {
				t.Fatal("workflow approval bypassed dispatch consent", err)
			}
			requireUntouchedFTPSWorkflow(t, f, s, d, listener, contacts)
			approveFTPS(t, f, s, d, reviewer, account)
			delegated, err := s.DispatchReviews(f.ctx, reviewer, "", 50)
			if err != nil || len(delegated.Reviews) != 1 {
				t.Fatal("reviewer private history", err)
			}
			review, err := s.DispatchReview(f.ctx, reviewer, delegated.Reviews[0].ID)
			if err != nil || review.Definition.Effect.Workflow == nil || review.Definition.Effect.Workflow.ConnectionHash != c.Hash {
				t.Fatal("review dropped registered binding", err)
			}
			if _, err = s.DispatchDelivery(f.ctx, reviewer, d.ID); !errors.Is(err, store.ErrForbidden) {
				t.Fatal("reviewer gained original delivery access", err)
			}
			if _, _, err = f.s.Custody.Download(f.ctx, reviewer, f.file.ID); !errors.Is(err, store.ErrForbidden) {
				t.Fatal("reviewer gained source bytes", err)
			}
			completed, err := f.s.Work(f.ctx, f.scope, run.ID, "worker")
			if err != nil || !completed.Replayed || completed.Status.ObservedState != "succeeded" {
				t.Fatal("approved original workflow did not finish", err)
			}
			readReceiverBytes(t, r, "/inbox/"+d.ID+"-payroll.csv")
			out, err := s.Status(f.ctx, f.scope, d.ID)
			if err != nil || out.Attempts != 1 || out.Fence != 1 {
				t.Fatal("wrong sending identity", err)
			}
			var receipt map[string]any
			if json.Unmarshal(out.Observation, &receipt) != nil || receipt["protocol"] != "ftps" || receipt["file_fsync_acknowledged"] != false || receipt["business_acceptance"] != "unknown" {
				t.Fatal("workflow inflated receiver receipt")
			}
			before := listener.contacts.Load()
			again, err := f.s.Work(f.ctx, f.scope, run.ID, "worker")
			if err != nil || !again.Replayed || again.Dispatch != completed.Dispatch || listener.contacts.Load() != before {
				t.Fatal("completed saved worker key resent bytes", err)
			}
		})
	}
}

func TestRegisteredFTPSWorkflowVersionRotationDoesNotRebindAndRevocationBlocks(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		mode := "explicit"
		if implicit {
			mode = "implicit"
		}
		t.Run(mode, func(t *testing.T) {
			f, s, reviewer, account := outboundFixture(t)
			_, spec, listener := governedFTPSReceiver(t, implicit)
			c := registeredFTPSConnection(t, f, spec)
			run, d := registeredFTPSRun(t, f, s, c, false)
			approveFTPS(t, f, s, d, reviewer, account)
			changed := spec
			changed.ReceiverContract.DocumentSHA256 = strings.Repeat("d", 64)
			next, err := f.s.RegisterConnection(f.ctx, f.scope, "rotate-ftps", ConnectionRequest{ID: c.ID, ExpectedVersion: c.Version, Directory: c.Directory, FTPS: &changed})
			if err != nil {
				t.Fatal(err)
			}
			var v ConnectionView
			if json.Unmarshal(next.Resource, &v) != nil || v.ID != c.ID || v.Version != c.Version+1 || v.Hash == c.Hash {
				t.Fatal("connection rotation did not create a new meaning")
			}
			requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
			if _, err = f.s.RevokeConnection(f.ctx, f.scope, c.ID, c.Version, "revoke-original", Decision{Hash: c.Hash, Revision: c.Revision}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.s.Work(f.ctx, f.scope, run.ID, "worker"); !errors.Is(err, store.ErrState) {
				t.Fatal("revoked original connection was bypassed", err)
			}
			requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
			current, err := f.s.Connection(f.ctx, f.scope, v.ID, v.Version)
			if err != nil || current.State != "active" || current.Hash != v.Hash {
				t.Fatal("revocation rewrote successor", err)
			}
		})
	}
}

func TestRegisteredFTPSWorkflowRejectsProtocolMismatchBeforeDraftOrContact(t *testing.T) {
	f, s, _, _ := outboundFixture(t)
	_, spec, listener := governedFTPSReceiver(t, false)
	c := registeredFTPSConnection(t, f, spec)
	for _, step := range []Step{
		{ID: "send", Kind: "sftp.deliver", Filename: "payroll.csv", Connection: Reference{ID: c.ID, Version: c.Version, Hash: c.Hash}},
		{ID: "send", Kind: "ftps.deliver", Filename: "payroll.csv", Connection: Reference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}},
	} {
		d := Definition{Schema: 1, Name: "Wrong registered protocol", Steps: []Step{step}}
		if _, err := f.s.Validate(f.ctx, f.scope, PreviewRequest{Definition: d}); !errors.Is(err, ErrInput) {
			t.Fatal("preview accepted mixed protocol", err)
		}
		if _, err := f.s.Draft(f.ctx, f.scope, secure.NewID(), DraftRequest{Definition: d}); !errors.Is(err, ErrInput) {
			t.Fatal("draft accepted mixed protocol", err)
		}
	}
	if listener.contacts.Load() != 0 {
		t.Fatal("invalid workflow contacted receiver")
	}
	if _, err := s.DispatchReviews(f.ctx, f.scope, "", 50); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredFTPSWorkflowLostRepliesRemainAmbiguousAndReadOnly(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		mode := "explicit"
		if implicit {
			mode = "implicit"
		}
		for _, phase := range []string{"stage", "rename"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				f, s, reviewer, account := outboundFixture(t)
				r, spec, listener := governedFTPSReceiver(t, implicit)
				c := registeredFTPSConnection(t, f, spec)
				run, d := registeredFTPSRun(t, f, s, c, false)
				approveFTPS(t, f, s, d, reviewer, account)
				stage := "/stage/.freightctl-" + d.ID + ".partial"
				final := "/inbox/" + d.ID + "-payroll.csv"
				cut := stage
				if phase == "rename" {
					cut = final
				}
				listener.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, cut); return err == nil })
				out, err := f.s.Work(f.ctx, f.scope, run.ID, "worker")
				if err != nil || out.Status.Steps[0].State != "ambiguous" || !listener.fired.Load() {
					t.Fatal("lost reply not retained by workflow", err)
				}
				before, err := s.Status(f.ctx, f.scope, d.ID)
				if err != nil {
					t.Fatal(err)
				}
				contacts := listener.contacts.Load()
				if _, err = f.s.Work(f.ctx, f.scope, run.ID, "worker"); !errors.Is(err, store.ErrState) || listener.contacts.Load() != contacts {
					t.Fatal("uncertain workflow resent bytes", err)
				}
				entry, err := r.s.Custody.StatPath(r.ctx, r.scope, cut)
				if err != nil {
					t.Fatal(err)
				}
				snapshot := snapshotReceiverReads(t, r)
				reconciled, err := s.Reconcile(f.ctx, f.scope, d.ID)
				if err != nil || reconciled.Attempts != before.Attempts || reconciled.Fence != before.Fence {
					t.Fatal("reconciliation changed sending identity", err)
				}
				if phase == "stage" && reconciled.State != "ambiguous" || phase == "rename" && reconciled.State != "succeeded" {
					t.Fatal("reconciliation invented or missed exact publication")
				}
				readReceiverBytes(t, r, cut)
				requireOnlyReceiverReadAudit(t, r, snapshot, snapshotReceiverReads(t, r), entry.FileID, phase, mode)
				if phase == "rename" {
					var receipt map[string]any
					json.Unmarshal(reconciled.Observation, &receipt)
					if receipt["rename_acknowledged"] != false || receipt["file_fsync_acknowledged"] != false {
						t.Fatal("read-only recovery invented a lost acknowledgment")
					}
					closed, err := f.s.RefreshRun(f.ctx, f.scope, run.ID, "recovered")
					if err != nil {
						t.Fatal(err)
					}
					var status struct {
						Status RunView `json:"status"`
					}
					if json.Unmarshal(closed.Resource, &status) != nil || status.Status.ObservedState != "succeeded" {
						t.Fatal("workflow did not derive success from recovered exact receipt")
					}
				}
			})
		}
	}
}

func TestRegisteredFTPSWorkflowBoundedProgramUsesTheSameConsentAndSender(t *testing.T) {
	f, s, reviewer, account := outboundFixture(t)
	r, spec, listener := governedFTPSReceiver(t, false)
	c := registeredFTPSConnection(t, f, spec)
	run, d := registeredFTPSRun(t, f, s, c, true)
	if len(run.Plan) == 0 || run.PlanHash == "" {
		t.Fatal("bounded program was not captured")
	}
	if _, err := f.s.Work(f.ctx, f.scope, run.ID, "worker"); !errors.Is(err, store.ErrDispatchApproval) {
		t.Fatal("program bypassed consent", err)
	}
	requireUntouchedFTPSWorkflow(t, f, s, d, listener, 0)
	approveFTPS(t, f, s, d, reviewer, account)
	out, err := f.s.Work(f.ctx, f.scope, run.ID, "worker")
	if err != nil || out.Status.ObservedState != "succeeded" {
		t.Fatal("captured FTPS program did not finish", err)
	}
	readReceiverBytes(t, r, "/inbox/"+d.ID+"-payroll.csv")
}

func TestRegisteredFTPSWorkflowSQLRejectsRewrittenProtocolAndConnection(t *testing.T) {
	f, s, _, _ := outboundFixture(t)
	_, config, _ := governedFTPSReceiver(t, false)
	c := registeredFTPSConnection(t, f, config)
	run, d := registeredFTPSRun(t, f, s, c, false)
	for _, protocol := range []bool{false, true} {
		tx, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		clone := *run
		clone.ID = secure.NewID()
		if err = tx.SaveWorkflowRun(f.ctx, &clone, 0); err != nil {
			tx.Tx.Rollback(f.ctx)
			t.Fatal(err)
		}
		var spec delivery.Definition
		if json.Unmarshal(d.Definition, &spec) != nil {
			t.Fatal("definition")
		}
		spec.Binding.RunID = clone.ID
		if protocol {
			row, e := tx.Configuration(f.ctx, true, f.connection.ID, f.connection.Version, false)
			if e != nil {
				t.Fatal(e)
			}
			ssh, e := connectionDefinition(row)
			if e != nil {
				t.Fatal(e)
			}
			spec.Schema = 1
			spec.FTPS = nil
			spec.Destination = ssh.Destination
		} else {
			spec.FTPS.Destination.Mode = "implicit"
		}
		encoded, hash, e := digest(spec)
		if e != nil {
			t.Fatal(e)
		}
		forged := *d
		forged.ID = secure.NewID()
		forged.Definition = encoded
		forged.DefinitionHash = hash
		forged.State = "draft"
		forged.Revision = 1
		if err = tx.SaveDelivery(f.ctx, &forged, 0); err == nil {
			err = tx.BindWorkflowStep(f.ctx, &store.WorkflowStep{RunID: clone.ID, ID: "send", Ordinal: 1, ConnectionID: c.ID, ConnectionVersion: c.Version, ConnectionHash: c.Hash, DeliveryID: forged.ID})
		}
		if err == nil {
			err = tx.Tx.Commit(f.ctx)
		} else {
			tx.Tx.Rollback(f.ctx)
		}
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23514" || pe.Message != "delivery requires exact workflow run, step, source and connection bindings" {
			t.Fatal("SQL protocol/connection refusal failed or had an unrelated cause", err)
		}
	}
}

func TestRegisteredFTPSWorkflowRevocationBlocksSavedWorkersAndAmbiguousReadback(t *testing.T) {
	for _, mode := range []string{"explicit", "implicit"} {
		for _, revoked := range []string{"connection", "workflow"} {
			for _, phase := range []string{"untouched-program", "ambiguous-rename"} {
				t.Run(mode+"/"+revoked+"/"+phase, func(t *testing.T) {
					f, sender, reviewer, account := outboundFixture(t)
					r, spec, listener := governedFTPSReceiver(t, mode == "implicit")
					c := registeredFTPSConnection(t, f, spec)
					run, d := registeredFTPSRun(t, f, sender, c, phase == "untouched-program")
					if _, err := f.s.Work(f.ctx, f.scope, run.ID, "revocation-worker"); !errors.Is(err, store.ErrDispatchApproval) {
						t.Fatal("worker key bypassed initial independent consent", err)
					}
					requireUntouchedFTPSWorkflow(t, f, sender, d, listener, 0)
					approveFTPS(t, f, sender, d, reviewer, account)
					if phase == "ambiguous-rename" {
						final := "/inbox/" + d.ID + "-payroll.csv"
						listener.setAfter(func() bool { _, err := r.s.Custody.StatPath(r.ctx, r.scope, final); return err == nil })
						out, err := f.s.Work(f.ctx, f.scope, run.ID, "revocation-worker")
						if err != nil || !out.Replayed || out.Status.Steps[0].State != "ambiguous" || !listener.fired.Load() {
							t.Fatal("actual lost rename reply was not retained", err)
						}
						readReceiverBytes(t, r, final)
					}
					before, err := sender.Status(f.ctx, f.scope, d.ID)
					if err != nil {
						t.Fatal(err)
					}
					contacts := listener.contacts.Load()
					receiver := snapshotReceiverReads(t, r)
					if revoked == "connection" {
						_, err = f.s.RevokeConnection(f.ctx, f.scope, c.ID, c.Version, "revoke-bound-connection", Decision{Hash: c.Hash, Revision: c.Revision})
					} else {
						var workflow *store.Configuration
						workflow, err = f.s.Configuration(f.ctx, f.scope, run.WorkflowID, run.WorkflowVersion)
						if err == nil {
							_, err = f.s.Decide(f.ctx, f.scope, workflow.ID, workflow.Version, "revoke-bound-workflow", "revoke", Decision{Hash: workflow.Hash, Revision: workflow.Revision})
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					if _, err = f.s.Work(f.ctx, f.scope, run.ID, "revocation-worker"); !errors.Is(err, store.ErrState) {
						t.Fatal("saved worker receipt bypassed current authority", err)
					}
					if phase == "ambiguous-rename" {
						if _, err = sender.Reconcile(f.ctx, f.scope, d.ID); !errors.Is(err, store.ErrState) {
							t.Fatal("read-only recovery bypassed revoked workflow or connection", err)
						}
					}
					after, err := sender.Status(f.ctx, f.scope, d.ID)
					if err != nil || !reflect.DeepEqual(before, after) || listener.contacts.Load() != contacts {
						t.Fatal("revoked work contacted receiver or changed the original intent", err)
					}
					if !reflect.DeepEqual(receiver, snapshotReceiverReads(t, r)) {
						t.Fatal("revoked observation changed receiver data or audit history")
					}
				})
			}
		}
	}
}
