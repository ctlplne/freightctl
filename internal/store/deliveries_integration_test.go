//go:build integration

package store

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestDeliveryMigrationEventsIsolationAndFencing(t *testing.T) {
	ctx, adminPath, runtimePath, passwordPath := migrationDatabase(t)
	if err := Migrate(ctx, adminPath, passwordPath); err != nil {
		t.Fatal(err)
	}
	scope := Scope{Tenant: secure.NewID(), Partner: secure.NewID()}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err := Provision(ctx, adminPath, scope.Tenant, scope.Partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	db, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	tx, err := db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	file := &File{ID: secure.NewID(), Size: 3, SHA256: secure.Digest([]byte("abc")), Policy: "integrity-only-v1"}
	if err = tx.Accept(ctx, "file", Meaning(file.Size, file.SHA256), file); err != nil {
		t.Fatal(err)
	}
	now, err := tx.DatabaseTime(ctx)
	if err != nil {
		t.Fatal(err)
	}
	d := &Delivery{ID: secure.NewID(), FileID: file.ID, Definition: json.RawMessage(`{"schema_version":1}`), DefinitionHash: secure.Digest([]byte("fixture")), State: "draft", Revision: 1, NextAt: now, Observation: json.RawMessage(`{}`)}
	if err = tx.SaveDelivery(ctx, d, 0); err != nil {
		t.Fatal(err)
	}
	if err = tx.DeliveryReceipt(ctx, "create", d.DefinitionHash, d); err != nil {
		t.Fatal(err)
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Existing v6 accounts never acquire outbound grants from a schema upgrade.
	admin, err := connect(ctx, adminPath)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var count int
	if err = admin.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relname IN ('delivery_intents','delivery_receipts') AND relrowsecurity AND relforcerowsecurity`).Scan(&count); err != nil || count != 2 {
		t.Fatal("delivery RLS", count, err)
	}
	mutate := func(next string, lease bool) {
		t.Helper()
		tx, err := db.Begin(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(ctx)
		got, err := tx.Delivery(ctx, d.ID, true)
		if err != nil {
			t.Fatal(err)
		}
		previous := got.Revision
		got.Revision++
		got.State = next
		if lease {
			now, err := tx.DatabaseTime(ctx)
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(70 * time.Millisecond)
			got.LeaseUntil = &until
			got.LeaseOwner = secure.NewID()
			got.Fence++
			got.Attempts++
		} else if next == "ambiguous" || next == "succeeded" {
			got.LeaseUntil = nil
			got.LeaseOwner = ""
		}
		if err = tx.SaveDelivery(ctx, got, previous); err != nil {
			t.Fatal(next, err)
		}
		if err = tx.Tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		d = got
	}
	mutate("queued", false)
	mutate("staging", true)
	staleFence, staleOwner := d.Fence, d.LeaseOwner
	time.Sleep(90 * time.Millisecond)
	mutate("staging", true)
	if d.Fence <= staleFence || d.LeaseOwner == staleOwner {
		t.Fatal("claim did not replace fence/owner")
	}
	// Even an exact matching event cannot renew a stale fence or skip publication.
	tx, err = db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tx.Delivery(ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	previous := got.Revision
	got.Revision++
	got.Fence = staleFence
	got.LeaseOwner = staleOwner
	err = tx.SaveDelivery(ctx, got, previous)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("stale fence accepted", err)
	}
	tx.Tx.Rollback(ctx)
	tx, err = db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Tx.Exec(ctx, `UPDATE delivery_intents SET observation='{"forged":true}' WHERE delivery_id=$1`, d.ID); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("unjournaled change accepted", err)
	}
	tx.Tx.Rollback(ctx)
	mutate("publishing", false)
	time.Sleep(90 * time.Millisecond)
	mutate("ambiguous", false)
	tx, err = db.Begin(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	got, err = tx.Delivery(ctx, d.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	previous = got.Revision
	got.Revision++
	got.State = "queued"
	if err = tx.SaveDelivery(ctx, got, previous); !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("ambiguous delivery automatically retried", err)
	}
	tx.Tx.Rollback(ctx)
	// A separate identity in the same tenant/partner cannot see drafts or receipts.
	otherPath := filepath.Join(t.TempDir(), "token")
	if err = secure.WriteToken(otherPath); err != nil {
		t.Fatal(err)
	}
	if err = Provision(ctx, adminPath, scope.Tenant, scope.Partner, otherPath); err != nil {
		t.Fatal(err)
	}
	otherSecret, err := secure.ReadSecret(otherPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	other := scope
	other.TokenHash = secure.Digest(otherSecret.Bytes)
	otherSecret.Close()
	tx, err = db.Begin(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(ctx)
	if _, err = tx.Delivery(ctx, d.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatal("actor isolation", err)
	}
	if err = tx.Tx.QueryRow(ctx, `SELECT count(*) FROM delivery_receipts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("receipt isolation", count, err)
	}
	_ = tx.Tx.Rollback(ctx)
	// Separate runtime pools model separate processes sharing the same capacity.
	otherDB, err := Open(ctx, runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	defer otherDB.Pool.Close()
	check1, release1, err := db.DeliveryWorkerSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release1()
	_, release2, err := otherDB.DeliveryWorkerSlot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if _, _, err = db.DeliveryWorkerSlot(ctx); !errors.Is(err, ErrLimit) {
		t.Fatal("database-wide worker budget exceeded", err)
	}
	if err = check1(); err != nil {
		t.Fatal(err)
	}
}
