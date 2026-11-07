//go:build integration

package store

import (
	"errors"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuthorityReadFenceKeepsRuntimeCredentialsReadOnlyAndAccountChangesSerialized(t *testing.T) {
	f := newBrowserFixture(t)
	tx, err := f.db.BeginApproval(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	var write, insert bool
	if err = tx.Tx.QueryRow(f.ctx, `SELECT has_table_privilege(current_user,'credentials','UPDATE'),has_table_privilege(current_user,'credentials','INSERT')`).Scan(&write, &insert); err != nil || write || insert {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("runtime gained direct credential write authority", err)
	}
	if _, err = tx.Tx.Exec(f.ctx, `SELECT freightctl_authority_read_lock($1,$2)`, f.scope.Tenant, f.scope.Partner); err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("owner transaction could not reuse account fence", err)
	}
	other, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		tx.Tx.Rollback(f.ctx)
		t.Fatal(err)
	}
	_, err = other.Tx.Exec(f.ctx, `SELECT freightctl_authority_read_lock($1,$2)`, f.scope.Tenant, f.scope.Partner)
	other.Tx.Rollback(f.ctx)
	var failure *pgconn.PgError
	if !errors.As(err, &failure) || failure.Code != "40001" {
		tx.Tx.Rollback(f.ctx)
		t.Fatal("late credential fence did not fail closed during account serialization", err)
	}
	tx.Tx.Rollback(f.ctx)
	tx, err = f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `SELECT freightctl_authority_read_lock($1,$2)`, secure.NewID(), f.scope.Partner)
	tx.Tx.Rollback(f.ctx)
	if !errors.As(err, &failure) || failure.Code != "42501" {
		t.Fatal("authority read fence accepted another scope", err)
	}
	tx, err = f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Tx.Exec(f.ctx, `UPDATE credentials SET namespace_root=namespace_root WHERE actor_id=$1`, tx.Actor)
	tx.Tx.Rollback(f.ctx)
	if !errors.As(err, &failure) || failure.Code != "42501" {
		t.Fatal("runtime directly updated a credential", err)
	}
	a, sender := endpointParticipant(t, f, []string{"read", "deliver"})
	b, _ := endpointParticipant(t, f, []string{"read", "list"})
	d := ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: b, Senders: []ExchangeParticipant{a}}
	created, err := f.db.RegisterExchangeEndpoint(f.ctx, f.scope, "read-only-credentials-register", ExchangeEndpointCommand{Operation: "create", ID: secure.NewID(), Definition: &d}, ExchangeLimits{MaxArtifactBytes: 1 << 20, MaxLifetime: time.Hour, MaxSenders: 16}, 2)
	if err != nil || created.Endpoint.Revision != 1 {
		t.Fatal("ordinary registration required forbidden credential mutation", err)
	}
	reader, err := f.db.Begin(f.ctx, sender)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Tx.Rollback(f.ctx)
	if err = reader.validateExchangeEndpointParticipants(f.ctx, d); err != nil {
		t.Fatal("ordinary participant validation required account-management lock", err)
	}
	writer, err := f.db.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Tx.Rollback(f.ctx)
	var exclusive bool
	if err = writer.Tx.QueryRow(f.ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, f.scope.Tenant+":"+f.scope.Partner+":accounts").Scan(&exclusive); err != nil || exclusive {
		t.Fatal("participant read did not fence a concurrent account writer", err)
	}
}
