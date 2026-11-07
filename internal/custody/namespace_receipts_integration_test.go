//go:build integration

package custody_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestNamespaceReceiptIsReadOnlyPrivateAndFencedAfterDestructiveCommit(t *testing.T) {
	f := setup(t)
	shared := uint32(0770)
	pathCommand(t, f, "receipt-mount", store.PathCommand{Operation: "mkdir", Path: "/receipt-mount", Mode: &shared})
	pathCommand(t, f, "receipt-other-root", store.PathCommand{Operation: "mkdir", Path: "/receipt-other", Mode: &shared})
	source := pathCommand(t, f, "receipt-source", store.PathCommand{Operation: "mkdir", Path: "/receipt-mount/source", Mode: &shared})
	manager := restrictedIdentity(t, f, []string{"read", "list", "manage_paths"}, "/receipt-mount")
	command := store.PathCommand{Operation: "remove_tree", Path: "/source", ExpectedEntryID: source.Entry.ID, ExpectedRevision: &source.Entry.Revision}
	result, err := f.service.PathCommand(f.ctx, manager, "receipt-original", command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/receipt-mount/source"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("receipt fixture did not remove source", err)
	}
	counts := func() [2]int64 {
		t.Helper()
		var rows [2]int64
		if err := f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2),(SELECT count(*) FROM namespace_commands WHERE tenant_id=$1 AND partner_id=$2)`, f.a.Tenant, f.a.Partner).Scan(&rows[0], &rows[1]); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	before := counts()
	expected := *result
	expected.Entry.Modified = expected.Entry.Modified.UTC()
	receipt, err := f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", command)
	if err != nil || receipt.Profile != "namespace-command-receipt-v1" || receipt.Observation != "original-commit-not-current-state" || receipt.Result.Replayed || !reflect.DeepEqual(receipt.Result, expected) || !store.ValidID(receipt.CompletedEventID) {
		t.Fatal("read-only lookup did not recover exact committed result", err)
	}
	again, err := f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", command)
	if err != nil || !reflect.DeepEqual(again, receipt) {
		t.Fatal("repeated receipt read changed historical evidence", err)
	}
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, f.a, "receipt-original", command); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("administrator could recover another actor's private receipt", err)
	}
	changed := command
	changed.Path = "/different"
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", changed); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("changed command meaning disclosed a receipt", err)
	}
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-unknown", command); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unknown key did not remain unknown", err)
	}
	if counts() != before {
		t.Fatal("read-only receipt lookup emitted events or commands")
	}
	tx, err := f.db.Begin(f.ctx, manager)
	if err != nil {
		t.Fatal(err)
	}
	actor := tx.Actor
	authority := tx.AuthorityRevision
	if err = tx.Tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Advance this exact task-fixture credential through the actual existing
	// SQL revision trigger. Never assign authority_revision or alter its guard.
	// This prepares scope-change negatives,not a control-plane API claim.
	var advanced int64
	if err = f.admin.QueryRow(f.ctx, `UPDATE credentials SET permissions=ARRAY['read','list','manage_paths','write']::text[] WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 RETURNING authority_revision`, f.a.Tenant, f.a.Partner, actor).Scan(&advanced); err != nil || advanced != authority+1 {
		t.Fatal("fixture did not advance actual authority revision", err)
	}
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", command); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("new authority recovered an old command meaning", err)
	}
	if _, err = f.admin.Exec(f.ctx, `UPDATE credentials SET namespace_root='/receipt-other' WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3`, f.a.Tenant, f.a.Partner, actor); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", command); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("changed mount recovered old private path evidence", err)
	}
	if _, err = f.admin.Exec(f.ctx, `UPDATE credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3`, f.a.Tenant, f.a.Partner, actor); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReadPathCommandReceipt(f.ctx, manager, "receipt-original", command); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("revoked credential recovered private receipt", err)
	}
	if counts() != before {
		t.Fatal("receipt lookup after scope/revocation changes wrote durable state")
	}
}
