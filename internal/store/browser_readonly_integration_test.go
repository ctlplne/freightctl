//go:build integration

package store

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestReadOnlyBrowserAuthenticationRetainsRowFenceAndRechecksLiveSession(t *testing.T) {
	f := newBrowserFixture(t)
	b, scope := f.create(t, "readonly-live-session", time.Minute)
	reader, err := f.db.begin(f.ctx, scope, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal("browser cannot authenticate a read-only observation", err)
	}
	defer reader.Tx.Rollback(f.ctx)
	var readOnly string
	if err = reader.Tx.QueryRow(f.ctx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil || readOnly != "on" {
		t.Fatal("read service received a writable transaction", readOnly, err)
	}
	if err = reader.Reauthorize(f.ctx); err != nil {
		t.Fatal("live reauthorization cannot reuse its held session fence", err)
	}
	writer, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	err = writer.Tx.QueryRow(f.ctx, `SELECT session_id::text FROM browser_sessions WHERE session_id=$1 FOR UPDATE NOWAIT`, b.ID).Scan(&id)
	writer.Tx.Rollback(f.ctx)
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != "55P03" {
		t.Fatal("read-only observation lost its real session row fence", err)
	}
	_, err = reader.Tx.Exec(f.ctx, `UPDATE browser_sessions SET state=state WHERE session_id=$1`, b.ID)
	if !errors.As(err, &failure) || failure.Code != "25006" {
		t.Fatal("read-only service could issue a domain mutation", err)
	}
	if err = reader.Tx.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.db.RevokeBrowserSession(f.ctx, scope, "readonly-logout"); err != nil {
		t.Fatal("released read fence prevented ordinary logout", err)
	}
	if _, err = f.db.SearchAuditHistory(f.ctx, scope, AuditHistoryRequest{Limit: 1}); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("captured browser proof survived logout in read-only history", err)
	}
	if _, err = f.db.SearchAuditHistory(f.ctx, f.scope, AuditHistoryRequest{Limit: 1}); err != nil {
		t.Fatal("browser logout revoked ordinary bearer observation", err)
	}
}
