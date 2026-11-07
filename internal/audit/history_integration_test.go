//go:build integration

package audit

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestAuditHistoryNativeTiePaginationFiltersPrivacyAndCurrentAuthority(t *testing.T) {
	f := fixture(t)
	identity, err := f.db.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	resource, at := secure.NewID(), time.Now().UTC().Truncate(time.Microsecond)
	ids := make([]string, 6)
	tx, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	for i := range ids {
		ids[i] = secure.NewID()
		_, err = tx.Tx.Exec(f.ctx, `INSERT INTO events(tenant_id,partner_id,event_id,actor_id,kind,resource_id,payload,happened_at) VALUES($1,$2,$3,$4,'AuditHistoryFixture',$5,'{"private_payload":"private-history-sentinel","request_key":"private-key-sentinel","host_path":"private-path-sentinel"}',$6)`, f.scope.Tenant, f.scope.Partner, ids[i], identity.Actor, resource, at)
		if err != nil {
			tx.Tx.Rollback(f.ctx)
			t.Fatal(err)
		}
	}
	if err = tx.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	slices.Sort(ids)
	counts := func() [4]int {
		t.Helper()
		tx, err := f.db.Begin(f.ctx, f.scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var n [4]int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events),(SELECT count(*) FROM files),(SELECT count(*) FROM idempotency),(SELECT count(*) FROM delivery_intents)`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := counts()
	r := store.AuditHistoryRequest{Limit: 2, Actor: identity.Actor, Resource: resource, Kinds: []string{"AuditHistoryFixture"}, From: at.Format(time.RFC3339Nano), Until: at.Add(time.Microsecond).Format(time.RFC3339Nano)}
	var seen []string
	firstCursor := ""
	for {
		page, err := f.db.SearchAuditHistory(f.ctx, f.scope, r)
		if err != nil || len(page.Events) > r.Limit || page.Tenant != f.scope.Tenant || page.Partner != f.scope.Partner || page.Reader != identity.Actor || page.Observation != "independent-page-observation" || page.Payloads != "omitted" {
			t.Fatal("native history scope or page contract", err)
		}
		raw, _ := json.Marshal(page)
		for _, forbidden := range []string{"private-history-sentinel", "private-key-sentinel", "private-path-sentinel", `"payload":`, `"request_key":`} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatal("history disclosed event payload", forbidden)
			}
		}
		for _, event := range page.Events {
			if !event.At.Equal(at) || event.Actor != identity.Actor || event.Resource != resource || event.Kind != "AuditHistoryFixture" {
				t.Fatal("filter changed exact recorded identity")
			}
			seen = append(seen, event.ID)
		}
		if len(seen) > 6 {
			t.Fatal("pagination loop or duplicate")
		}
		if page.Next == "" {
			break
		}
		if firstCursor == "" {
			firstCursor = page.Next
		}
		r.After = page.Next
		r.Limit = 3
	}
	if !slices.Equal(seen, ids) || firstCursor == "" {
		t.Fatal("same-time keyset skipped or repeated immutable event")
	}
	r.After = ""
	r.From = at.Add(time.Microsecond).Format(time.RFC3339Nano)
	r.Until = at.Add(2 * time.Microsecond).Format(time.RFC3339Nano)
	if page, err := f.db.SearchAuditHistory(f.ctx, f.scope, r); err != nil || len(page.Events) != 0 || page.Next != "" {
		t.Fatal("half-open time filter changed", err)
	}
	r.From = at.Format(time.RFC3339Nano)
	r.Until = at.Add(time.Microsecond).Format(time.RFC3339Nano)
	r.After = firstCursor
	r.Kinds = []string{"AuditHistoryFixture", "DifferentFilter"}
	if _, err = f.db.SearchAuditHistory(f.ctx, f.scope, r); !errors.Is(err, store.ErrConflict) {
		t.Fatal("cursor accepted changed filters", err)
	}
	r.Kinds = []string{"AuditHistoryFixture"}
	if _, err = f.db.SearchAuditHistory(f.ctx, f.other, r); !errors.Is(err, store.ErrConflict) {
		t.Fatal("cursor crossed authenticated scope", err)
	}
	r.After = ""
	if page, err := f.db.SearchAuditHistory(f.ctx, f.other, r); err != nil || len(page.Events) != 0 {
		t.Fatal("other tenant saw source metadata", err)
	}
	if counts() != before {
		t.Fatal("history search wrote events,files,receipts or intents")
	}
	// A confined account root must already exist in the ordinary namespace.
	// Create it after the read-only search cardinality assertion above.
	directory, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Tx.Rollback(f.ctx)
	created, err := directory.ApplyPathCommand(f.ctx, "history-reader-directory", store.PathCommand{Operation: "mkdir", Path: "/confined"}, 1000)
	if err != nil || created.Entry.Kind != "dir" || created.Entry.Path != "/confined" {
		t.Fatal("confined reader namespace unavailable", err)
	}
	if err = directory.Tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"/confined", "/"} {
		actor, hash := secure.NewID(), secure.Digest([]byte(secure.NewID()))
		policy := store.AccountPolicy{Label: "explicit audit reader", Root: root, Permissions: []string{"read", "list", "audit_read"}}
		if _, err = f.db.ChangeAccount(f.ctx, f.scope, "history-reader-"+actor, store.AccountCommand{Operation: "create", ID: actor, CredentialHash: hash, Policy: &policy}); err != nil {
			t.Fatal(err)
		}
		reader := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: hash}
		page, err := f.db.SearchAuditHistory(f.ctx, reader, r)
		if root != "/" {
			if !errors.Is(err, store.ErrForbidden) {
				t.Fatal("confined reader acquired full-scope audit", err)
			}
			continue
		}
		if err != nil || len(page.Events) != 3 {
			t.Fatal("explicit root audit reader refused", err)
		}
		policy.Permissions = []string{"read", "list"}
		if _, err = f.db.ChangeAccount(f.ctx, f.scope, "revoke-history-"+actor, store.AccountCommand{Operation: "update", ID: actor, ExpectedRevision: 1, Policy: &policy}); err != nil {
			t.Fatal(err)
		}
		if _, err = f.db.SearchAuditHistory(f.ctx, reader, r); !errors.Is(err, store.ErrForbidden) {
			t.Fatal("revoked audit role retained search", err)
		}
	}
}
