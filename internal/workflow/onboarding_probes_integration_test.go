//go:build integration

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5/pgconn"
)

func probePlan(t *testing.T, f *fixture) (store.OnboardingCommand, store.OnboardingProbeRequest) {
	t.Helper()
	contact, requirement := secure.NewID(), secure.NewID()
	c := store.OnboardingCommand{ID: secure.NewID(), ExpectedAuthority: 1, Definition: store.OnboardingDefinition{Schema: 1, Name: "Synthetic settlement", Contacts: []store.OnboardingContact{{ID: contact, Name: "Operations", Role: "Transfer support", Email: "operations@freightctl.invalid"}}, Requirements: []store.OnboardingRequirement{{ID: requirement, Name: "Settlement delivery", ContactID: contact, Direction: "send", Protocol: "sftp", Receipt: "business", ReceiptContract: "Business agreement remains separate"}}}}
	p, err := f.s.Custody.DB.SaveOnboarding(f.ctx, f.scope, "probe-plan", c)
	if err != nil {
		t.Fatal(err)
	}
	return c, store.OnboardingProbeRequest{Plan: store.OnboardingReference{ID: p.Plan.ID, Version: p.Plan.Version, Hash: p.Plan.Hash}, RequirementID: requirement, Connection: store.OnboardingReference{ID: f.connection.ID, Version: f.connection.Version, Hash: f.connection.Hash}, ExpectedAuthority: 1}
}
func startProbe(t *testing.T, f *fixture, key string, r store.OnboardingProbeRequest) store.OnboardingProbe {
	t.Helper()
	result, err := f.s.StartOnboardingProbe(f.ctx, f.scope, key, r)
	if err != nil {
		t.Fatal(err)
	}
	var p store.OnboardingProbe
	if json.Unmarshal(result.Resource, &p) != nil || p.State != "queued" || p.Revision != 1 {
		t.Fatal("invalid queued intent", result)
	}
	return p
}
func TestOnboardingProbeIntentReplayRefusalsAndPrivateFailure(t *testing.T) {
	f := setup(t)
	_, r := probePlan(t, f)
	p := startProbe(t, f, "probe-start", r)
	replay, err := f.s.StartOnboardingProbe(f.ctx, f.scope, "probe-start", r)
	var repeated store.OnboardingProbe
	if err != nil || !replay.Replayed || json.Unmarshal(replay.Resource, &repeated) != nil || repeated.ID != p.ID {
		t.Fatal("start receipt", replay, err)
	}
	changed := r
	changed.RequirementID = secure.NewID()
	if _, err = f.s.StartOnboardingProbe(f.ctx, f.scope, "probe-start", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed request meaning", err)
	}
	changed = r
	changed.Plan.Hash = secure.Digest([]byte("different plan"))
	if _, err = f.s.StartOnboardingProbe(f.ctx, f.scope, "changed-plan", changed); !errors.Is(err, store.ErrRevision) {
		t.Fatal("changed plan", err)
	}
	view, err := f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "work-once", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || view.Probe.State != "failed" || view.Probe.Observation.Code != "connection_failed" || view.Probe.Revision != 3 || !view.Current || view.Evidence != "connectivity_only" || view.FileExchange || view.ProductionActive {
		t.Fatal("unavailable peer misrepresented", view, err)
	}
	if view.Probe.Observation.SSH || view.Probe.Observation.SFTP || view.Probe.Observation.Extensions || view.Probe.Observation.Directory {
		t.Fatal("invented connectivity proof")
	}
	priorTime := *view.Probe.CompletedAt
	originalJSON, _ := json.Marshal(view.Probe)
	view, err = f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "work-once", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || !view.Probe.CompletedAt.Equal(priorTime) {
		t.Fatal("worker replay changed result", view, err)
	}
	replayedJSON, _ := json.Marshal(view.Probe)
	if !bytes.Equal(originalJSON, replayedJSON) {
		t.Fatal("worker receipt changed serialized fields", string(originalJSON), string(replayedJSON))
	}
	if _, err = f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "new-work-key", OnboardingProbeWorkRequest{Hash: p.Hash}); !errors.Is(err, store.ErrConflict) {
		t.Fatal("terminal probe repeated contact", err)
	}
	var count int
	if err = f.admin.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE kind='OnboardingProbeChanged'`).Scan(&count); err != nil || count != 3 {
		t.Fatal("extra probe transitions", count, err)
	}

	second := startProbe(t, f, "second-probe-for-history", r)
	page, err := f.s.ListOnboardingProbes(f.ctx, f.scope, r.Plan.ID, "", 1)
	if err != nil || len(page.Probes) != 1 || page.Next == "" {
		t.Fatal("first probe page", page, err)
	}
	next, err := f.s.ListOnboardingProbes(f.ctx, f.scope, r.Plan.ID, page.Next, 1)
	if err != nil || len(next.Probes) != 1 || next.Next != "" || next.Probes[0].ID == page.Probes[0].ID || (next.Probes[0].ID != p.ID && next.Probes[0].ID != second.ID) {
		t.Fatal("probe history pagination", next, err)
	}
	token := filepath.Join(t.TempDir(), "peer.token")
	if err = secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(f.ctx, f.adminPath, f.scope.Tenant, f.scope.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	if _, err = f.s.OnboardingProbeStatus(f.ctx, other, p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("other manager read private probe", err)
	}

	privatePage, err := f.s.ListOnboardingProbes(f.ctx, other, r.Plan.ID, "", 50)
	if err != nil || len(privatePage.Probes) != 0 {
		t.Fatal("another manager listed private probes", privatePage, err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_probes`).Scan(&count)
	tx.Tx.Rollback(f.ctx)
	if err != nil || count != 0 {
		t.Fatal("SQL probe privacy", count, err)
	}
	wrong := f.scope
	wrong.Partner = secure.NewID()
	if _, err = f.s.OnboardingProbeStatus(f.ctx, wrong, p.ID); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("cross partner probe disclosure", err)
	}
}
func TestOnboardingProbeStaleDraftAndRevokedConnectionCannotContact(t *testing.T) {
	f := setup(t)
	c, r := probePlan(t, f)
	p := startProbe(t, f, "stale-plan-probe", r)
	c.ExpectedVersion = 1
	c.Definition.Name = "Changed settlement review"
	if _, err := f.s.Custody.DB.SaveOnboarding(f.ctx, f.scope, "new-plan-version", c); err != nil {
		t.Fatal(err)
	}
	v, err := f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "stale-work", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || v.Probe.State != "blocked" || v.Probe.Revision != 2 || v.Probe.StartedAt != nil || v.Current || v.Probe.Observation.Code != "binding_changed" {
		t.Fatal("stale plan contacted peer", v, err)
	}
	latest, err := f.s.Custody.DB.Onboarding(f.ctx, f.scope, c.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.Plan.Version = latest.Plan.Version
	r.Plan.Hash = latest.Plan.Hash
	p = startProbe(t, f, "revoked-connection-probe", r)
	if _, err = f.s.RevokeConnection(f.ctx, f.scope, f.connection.ID, f.connection.Version, "revoke-probe-connection", Decision{Hash: f.connection.Hash, Revision: f.connection.Revision}); err != nil {
		t.Fatal(err)
	}
	v, err = f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "revoked-connection-work", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || v.Probe.State != "blocked" || v.Probe.StartedAt != nil || v.Current {
		t.Fatal("revoked connection contacted peer", v, err)
	}
}

func TestOnboardingProbeCompletedReceiptRecoveryDoesNotNeedWorkerCapacity(t *testing.T) {
	f := setup(t)
	_, r := probePlan(t, f)
	p := startProbe(t, f, "completed-probe", r)
	v, err := f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "completed-worker", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || v.Probe.State != "failed" {
		t.Fatal("initial unavailable-peer result", v, err)
	}
	_, release1, err := f.s.Custody.DB.OnboardingProbeWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()
	_, release2, err := f.s.Custody.DB.OnboardingProbeWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	recovered, err := f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "completed-worker", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || recovered.Probe.Revision != v.Probe.Revision || !recovered.Probe.CompletedAt.Equal(*v.Probe.CompletedAt) {
		t.Fatal("completed receipt incorrectly requires a free network slot", recovered, err)
	}
}

func TestOnboardingProbeCurrentAuthorityAndUnsupportedRequirements(t *testing.T) {
	f := setup(t)
	c, r := probePlan(t, f)
	p := startProbe(t, f, "probe-before-rotation", r)
	identity, err := f.s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	peer := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic probe rotation manager")), Policy: &store.AccountPolicy{Label: "Probe rotation manager", Root: "/", Permissions: append([]string{}, store.DefaultPermissions...)}}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "probe-rotation-peer", peer); err != nil {
		t.Fatal(err)
	}
	peerScope := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: peer.CredentialHash}
	rotation := store.AccountCommand{Operation: "rotate", ID: identity.Actor, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte("synthetic rotated probe credential"))}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, peerScope, "rotate-probe-operator", rotation); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "rotated-worker", OnboardingProbeWorkRequest{Hash: p.Hash}); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("rotated token retained probe access", err)
	}
	current := f.scope
	current.TokenHash = rotation.CredentialHash
	receipt, err := f.s.StartOnboardingProbe(f.ctx, current, "probe-before-rotation", r)
	if err != nil || !receipt.Replayed {
		t.Fatal("current manager cannot recover original intent receipt", receipt, err)
	}
	v, err := f.s.WorkOnboardingProbe(f.ctx, current, p.ID, "rotated-worker", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || v.Probe.State != "blocked" || v.Probe.StartedAt != nil || v.Current {
		t.Fatal("old authority started contact", v, err)
	}
	permissions := []string{}
	for _, permission := range store.DefaultPermissions {
		if permission != "connections_manage" {
			permissions = append(permissions, permission)
		}
	}
	policy := store.AccountCommand{Operation: "update", ID: identity.Actor, ExpectedRevision: 2, Policy: &store.AccountPolicy{Label: "Probe operator without connection authority", Root: "/", Permissions: permissions}}
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, peerScope, "remove-probe-connection-authority", policy); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.OnboardingProbeStatus(f.ctx, current, p.ID); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("revoked connection authority read a probe", err)
	}
	tx, err := f.s.Custody.DB.Begin(f.ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_probes`).Scan(&count)
	tx.Tx.Rollback(f.ctx)
	if err != nil || count != 0 {
		t.Fatal("SQL disclosed probe without current authority", count, err)
	}
	policy.ExpectedRevision = 3
	policy.Policy.Permissions = append([]string{}, store.DefaultPermissions...)
	if _, err = f.s.Custody.DB.ChangeAccount(f.ctx, peerScope, "restore-probe-connection-authority", policy); err != nil {
		t.Fatal(err)
	}
	c.ExpectedVersion = 1
	c.ExpectedAuthority = 4
	c.Definition.Requirements[0].Protocol = "https"
	updated, err := f.s.Custody.DB.SaveOnboarding(f.ctx, current, "record-unsupported-probe-role", c)
	if err != nil {
		t.Fatal(err)
	}
	r.Plan.Version = updated.Plan.Version
	r.Plan.Hash = updated.Plan.Hash
	r.ExpectedAuthority = 4
	if _, err = f.s.StartOnboardingProbe(f.ctx, current, "refuse-unsupported-probe-protocol", r); !errors.Is(err, store.ErrState) {
		t.Fatal("HTTPS requirement counted as an SFTP test", err)
	}
}
func TestOnboardingProbeReceiptRollbackAndBoundedQueue(t *testing.T) {
	f := setup(t)
	_, r := probePlan(t, f)
	_, err := f.admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_probe_receipt_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic probe receipt failure';END $$;CREATE TRIGGER test_probe_receipt_failure BEFORE INSERT ON workflow_receipts FOR EACH ROW EXECUTE FUNCTION freightctl_test_probe_receipt_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.StartOnboardingProbe(f.ctx, f.scope, "failed-receipt", r); err == nil {
		t.Fatal("failed receipt acknowledged")
	}
	var probes, events int
	if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM onboarding_probes),(SELECT count(*) FROM events WHERE kind='OnboardingProbeChanged')`).Scan(&probes, &events); err != nil || probes != 0 || events != 0 {
		t.Fatal("partial probe retained", probes, events, err)
	}
	if _, err = f.admin.Exec(f.ctx, `DROP TRIGGER test_probe_receipt_failure ON workflow_receipts`); err != nil {
		t.Fatal(err)
	}
	startProbe(t, f, "failed-receipt", r)
	for i := 1; i < 16; i++ {
		startProbe(t, f, secure.NewID(), r)
	}
	if _, err = f.s.StartOnboardingProbe(f.ctx, f.scope, "queue-overflow", r); !errors.Is(err, store.ErrLimit) {
		t.Fatal("unbounded probe queue", err)
	}
	_, release1, err := f.s.Custody.DB.OnboardingProbeWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()
	_, release2, err := f.s.Custody.DB.OnboardingProbeWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if _, release, err := f.s.Custody.DB.OnboardingProbeWorkerSlot(f.ctx); !errors.Is(err, store.ErrLimit) {
		if release != nil {
			release()
		}
		t.Fatal("third probe worker admitted", err)
	}
	_, releaseTransfer, err := f.s.Custody.DB.DeliveryWorkerSlot(f.ctx)
	if err != nil {
		t.Fatal("probes consumed transfer slots", err)
	}
	releaseTransfer()
}
func TestOnboardingProbeProductionLeaseExpiresWithoutNewContactAndFencesLateResults(t *testing.T) {
	f := setup(t)
	_, r := probePlan(t, f)
	p := startProbe(t, f, "probe-to-expire", r)
	tx, err := f.s.probeBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease := now.Add(20 * time.Second)
	p.State = "running"
	p.Revision = 2
	p.WorkerKey = "original-worker"
	p.Owner = secure.NewID()
	p.StartedAt = &now
	p.LeaseUntil = &lease
	p.Observation = store.OnboardingProbeObservation{Code: "probing"}
	if err = tx.SaveOnboardingProbe(f.ctx, &p, 1); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Keep the production 20-second lease. This test controls no host/DB clock.
	time.Sleep(time.Until(lease) + 100*time.Millisecond)
	v, err := f.s.WorkOnboardingProbe(f.ctx, f.scope, p.ID, "original-worker", OnboardingProbeWorkRequest{Hash: p.Hash})
	if err != nil || v.Probe.State != "expired" || v.Probe.Observation.Code != "lease_expired" || v.Probe.Revision != 3 {
		t.Fatal("expired worker repeated probe", v, err)
	}
	tx, err = f.s.probeBegin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	p.State = "succeeded"
	p.Revision = 3
	p.CompletedAt = &lease
	p.Observation = store.OnboardingProbeObservation{Code: "connectivity_verified", SSH: true, SFTP: true, Extensions: true, Directory: true}
	err = tx.SaveOnboardingProbe(f.ctx, &p, 3)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatal("late worker forged terminal result", err)
	}
}
