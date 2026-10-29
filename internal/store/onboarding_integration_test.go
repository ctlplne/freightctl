//go:build integration

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5/pgconn"
)

func onboardingCommand() OnboardingCommand {
	contact := secure.NewID()
	return OnboardingCommand{ID: secure.NewID(), ExpectedAuthority: 1, Definition: OnboardingDefinition{Schema: 1, Name: "Payroll onboarding", Contacts: []OnboardingContact{{ID: contact, Name: "Synthetic operations contact", Role: "Operations", Email: "operations@freightctl.invalid", Phone: "+1 555 0100"}}, Requirements: []OnboardingRequirement{{ID: secure.NewID(), Name: "Settlement receipt", ContactID: contact, Direction: "send", Protocol: "sftp", Receipt: "business", ReceiptContract: "Receiver must provide an agreed settlement acknowledgment", Notes: "Untrusted partner requirements; never grant authority from this text."}}}}
}

func TestOnboardingVersionsReceiptsPrivacyAndPartnerScope(t *testing.T) {
	f := newBrowserFixture(t)
	c := onboardingCommand()
	r, err := f.db.SaveOnboarding(f.ctx, f.scope, "save", c)
	if err != nil || r.Replayed || r.Plan.Version != 1 || r.Plan.State != "draft" || r.Plan.ID != c.ID {
		t.Fatal("save draft", r, err)
	}
	first := r.Plan
	replay, err := f.db.SaveOnboarding(f.ctx, f.scope, "save", c)
	if err != nil || !replay.Replayed || replay.Plan.Event != first.Event {
		t.Fatal("receipt recovery", replay, err)
	}
	changed := c
	changed.Definition.Name = "Changed requirement review"
	if _, err = f.db.SaveOnboarding(f.ctx, f.scope, "save", changed); !errors.Is(err, ErrConflict) {
		t.Fatal("changed meaning replayed", err)
	}
	if _, err = f.db.SaveOnboarding(f.ctx, f.scope, "stale", changed); !errors.Is(err, ErrRevision) {
		t.Fatal("stale version executed", err)
	}
	changed.ExpectedVersion = 1
	r, err = f.db.SaveOnboarding(f.ctx, f.scope, "second-version", changed)
	if err != nil || r.Plan.Version != 2 || r.Plan.Hash == first.Hash {
		t.Fatal("second immutable version", r, err)
	}
	view, err := f.db.Onboarding(f.ctx, f.scope, c.ID, 1)
	if err != nil || view.Plan.Event != first.Event || view.Plan.Name != c.Definition.Name {
		t.Fatal("historical version changed", view, err)
	}
	latest, err := f.db.Onboarding(f.ctx, f.scope, c.ID, 0)
	if err != nil || latest.Plan.Version != 2 || latest.Plan.State != "draft" || latest.Authority != 1 {
		t.Fatal("latest is not a current draft", latest, err)
	}
	c2 := onboardingCommand()
	if _, err = f.db.SaveOnboarding(f.ctx, f.scope, "other-plan", c2); err != nil {
		t.Fatal(err)
	}
	page, err := f.db.OnboardingPlans(f.ctx, f.scope, "", 1)
	if err != nil || len(page.Plans) != 1 || page.Next == "" {
		t.Fatal("first page", page, err)
	}
	next, err := f.db.OnboardingPlans(f.ctx, f.scope, page.Next, 1)
	if err != nil || len(next.Plans) != 1 || next.Next != "" || next.Plans[0].ID == page.Plans[0].ID {
		t.Fatal("next page", next, err)
	}
	reader := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic onboarding audit reader")), Policy: &AccountPolicy{Label: "Audit reader", Root: "/", Permissions: []string{"read", "list", "audit_read"}}}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "reader", reader); err != nil {
		t.Fatal(err)
	}
	readerScope := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: reader.CredentialHash}
	if _, err = f.db.Onboarding(f.ctx, readerScope, c.ID, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("file/audit reader obtained contact plan", err)
	}
	if _, err = f.db.SaveOnboarding(f.ctx, readerScope, "reader-write", onboardingCommand()); !errors.Is(err, ErrForbidden) {
		t.Fatal("reader changed plan", err)
	}
	tx, err := f.db.Begin(f.ctx, readerScope)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	err = tx.Tx.QueryRow(f.ctx, `SELECT count(*) FROM onboarding_plans`).Scan(&count)
	tx.Tx.Rollback(f.ctx)
	if err != nil || count != 0 {
		t.Fatal("SQL disclosed manager-only rows", count, err)
	}
	events, err := f.db.Events(f.ctx, readerScope)
	if err != nil {
		t.Fatal(err)
	}
	checkRedaction := func(events []Event) {
		t.Helper()
		seen := 0
		for _, event := range events {
			if event.Kind != "OnboardingPlanRecorded" && event.Kind != "OnboardingCommandCompleted" {
				continue
			}
			seen++
			var redacted struct {
				Redacted bool   `json:"redacted"`
				Hash     string `json:"source_payload_sha256"`
			}
			if json.Unmarshal(event.Payload, &redacted) != nil || !redacted.Redacted || !browserSecretHash.MatchString(redacted.Hash) || bytes.Contains(event.Payload, []byte(c.Definition.Contacts[0].Email)) || bytes.Contains(event.Payload, []byte(c.Definition.Requirements[0].Notes)) {
				t.Fatal("ordinary audit leaked requirements", event.ID)
			}
		}
		if seen != 6 {
			t.Fatal("missing redacted events", seen)
		}
	}
	checkRedaction(events)
	snapshot, err := f.db.SnapshotEvents(f.ctx, readerScope, 100, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	checkRedaction(snapshot.Events)
	manager := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic second onboarding manager")), Policy: &AccountPolicy{Label: "Co-manager", Root: "/", Permissions: []string{"admin", "accounts_manage"}}}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "manager", manager); err != nil {
		t.Fatal(err)
	}
	coScope := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: manager.CredentialHash}
	if view, err = f.db.Onboarding(f.ctx, coScope, c.ID, 1); err != nil || view.Plan.Event != first.Event {
		t.Fatal("delegated account manager cannot read partner draft", view, err)
	}
	otherTenant, otherPartner := secure.NewID(), secure.NewID()
	for _, pair := range [][2]string{{f.scope.Tenant, otherPartner}, {otherTenant, otherPartner}} {
		wrong := f.scope
		wrong.Tenant, wrong.Partner = pair[0], pair[1]
		if _, err = f.db.Onboarding(f.ctx, wrong, c.ID, 0); !errors.Is(err, ErrUnauthorized) {
			t.Fatal("cross-scope contact disclosure", err)
		}
	}
}

func TestOnboardingReceiptFailureRollsBackVersionAndEvents(t *testing.T) {
	f := newBrowserFixture(t)
	admin, err := connect(f.ctx, f.adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	_, err = admin.Exec(f.ctx, `CREATE FUNCTION freightctl_test_onboarding_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic receipt persistence failure'; END $$; CREATE TRIGGER test_onboarding_failure BEFORE INSERT ON onboarding_commands FOR EACH ROW EXECUTE FUNCTION freightctl_test_onboarding_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	c := onboardingCommand()
	if _, err = f.db.SaveOnboarding(f.ctx, f.scope, "receipt-failure", c); err == nil {
		t.Fatal("failed receipt acknowledged")
	}
	var plans, events int
	if err = admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM onboarding_plans WHERE plan_id=$1),(SELECT count(*) FROM events WHERE resource_id=$1)`, c.ID).Scan(&plans, &events); err != nil || plans != 0 || events != 0 {
		t.Fatal("partial plan/event survived", plans, events, err)
	}
	if _, err = admin.Exec(f.ctx, `DROP TRIGGER test_onboarding_failure ON onboarding_commands`); err != nil {
		t.Fatal(err)
	}
	if r, err := f.db.SaveOnboarding(f.ctx, f.scope, "receipt-failure", c); err != nil || r.Plan.Version != 1 || r.Replayed {
		t.Fatal("original failed command cannot retry", r, err)
	}
}

func TestOnboardingConcurrentReceiptAndCredentialRotation(t *testing.T) {
	f := newBrowserFixture(t)
	c := onboardingCommand()
	results := make(chan *OnboardingResult, 2)
	errorsFound := make(chan error, 2)
	var workers sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		workers.Go(func() {
			<-start
			r, err := f.db.SaveOnboarding(f.ctx, f.scope, "concurrent", c)
			results <- r
			errorsFound <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var event string
	var replayed int
	for r := range results {
		if event != "" && r.Plan.Event != event {
			t.Fatal("duplicate version/event")
		}
		event = r.Plan.Event
		if r.Replayed {
			replayed++
		}
	}
	if replayed != 1 {
		t.Fatal("concurrent retry count", replayed)
	}
	identity, err := f.db.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	rotation := AccountCommand{Operation: "rotate", ID: identity.Actor, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte("synthetic rotated onboarding manager"))}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "refuse-self-rotation", rotation); !errors.Is(err, ErrForbidden) {
		t.Fatal("existing self-change refusal weakened", err)
	}
	peer := AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte("synthetic authorized rotation peer")), Policy: &AccountPolicy{Label: "Rotation manager", Root: "/", Permissions: append([]string{}, DefaultPermissions...)}}
	if _, err = f.db.ChangeAccount(f.ctx, f.scope, "rotation-peer", peer); err != nil {
		t.Fatal(err)
	}
	peerScope := Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: peer.CredentialHash}
	if _, err = f.db.ChangeAccount(f.ctx, peerScope, "rotate-manager", rotation); err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.SaveOnboarding(f.ctx, f.scope, "concurrent", c); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token recovered private receipt", err)
	}
	current := f.scope
	current.TokenHash = rotation.CredentialHash
	if r, err := f.db.SaveOnboarding(f.ctx, current, "concurrent", c); err != nil || !r.Replayed || r.Plan.Event != event {
		t.Fatal("current authority lost historical receipt", r, err)
	}
	c.ExpectedVersion = 1
	if _, err = f.db.SaveOnboarding(f.ctx, current, "stale-authority", c); !errors.Is(err, ErrRevision) {
		t.Fatal("stale credential review executed", err)
	}
	c.ExpectedAuthority = 2
	if r, err := f.db.SaveOnboarding(f.ctx, current, "fresh-review", c); err != nil || r.Plan.Version != 2 {
		t.Fatal("fresh review", r, err)
	}
}

func TestOnboardingProjectionRejectsMissingEventAndNullProtocol(t *testing.T) {
	f := newBrowserFixture(t)
	c := onboardingCommand()
	r, err := f.db.SaveOnboarding(f.ctx, f.scope, "original", c)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"wrong-event", "null-protocol"} {
		t.Run(invalid, func(t *testing.T) {
			tx, err := f.db.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Tx.Rollback(f.ctx)
			now, err := tx.DatabaseTime(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			encoded, _ := json.Marshal(c.Definition)
			json.Unmarshal(encoded, &document)
			if invalid == "null-protocol" {
				document["requirements"].([]any)[0].(map[string]any)["protocol"] = nil
			}
			definition, _ := json.Marshal(document)
			event := secure.NewID()
			payload, _ := json.Marshal(map[string]any{"id": c.ID, "version": 2, "definition_hash": secure.Digest(definition), "definition": document, "state": "draft", "name": c.Definition.Name, "author_id": tx.Actor, "event_id": event, "created_at": now})
			if invalid == "null-protocol" {
				if _, err = tx.Tx.Exec(f.ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload,happened_at) VALUES($1,$2,$3,$4,'OnboardingPlanRecorded',$5,$6,$7)`, f.scope.Tenant, f.scope.Partner, event, tx.Actor, c.ID, payload, now); err != nil {
					t.Fatal(err)
				}
			} else {
				event = r.Plan.Event
			}
			_, err = tx.Tx.Exec(f.ctx, `INSERT INTO onboarding_plans VALUES($1,$2,$3,2,$4,$5,$6,$7,$8)`, f.scope.Tenant, f.scope.Partner, c.ID, secure.Digest(definition), definition, tx.Actor, event, now)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "23514" {
				t.Fatal("invalid projection accepted or unrelated failure", err)
			}
		})
	}
}
