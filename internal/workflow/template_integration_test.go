//go:build integration

package workflow

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Initialize the empty schema once, then copy it into a separate database for
// EVERY fixture. No tenant, account, event, file or sequence state is shared.
// Each clone still runs Migrate's exact checksum verification and Store.Open's
// real runtime-role/RLS checks. Cold migration/upgrade tests in store are intact.
var workflowTemplate struct {
	once                    sync.Once
	name, private, adminRef string
	created                 bool
	err                     error
}

func TestMain(m *testing.M) {
	// Lazy initialization matters: local -run '^$' compilation and pure contract
	// checks must not open PostgreSQL or create any template resource.
	code := m.Run()
	if err := cleanupWorkflowTemplate(); err != nil {
		fmt.Fprintln(os.Stderr, "task-owned workflow template cleanup failed")
		code = 1
	}
	os.Exit(code)
}

func templateConnection(ctx context.Context, ref string) (*pgx.Conn, error) {
	secret, err := secure.ReadSecret(ref, 4096)
	if err != nil {
		return nil, err
	}
	defer secret.Close()
	return pgx.Connect(ctx, string(secret.Bytes))
}

func workflowTemplateName(ctx context.Context, admin *pgxpool.Pool, adminRef string) (string, error) {
	workflowTemplate.once.Do(func() { workflowTemplate.err = initializeWorkflowTemplate(ctx, admin, adminRef) })
	return workflowTemplate.name, workflowTemplate.err
}

func initializeWorkflowTemplate(ctx context.Context, admin *pgxpool.Pool, adminRef string) error {
	workflowTemplate.adminRef = adminRef
	workflowTemplate.name = "freightctl_workflow_template_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{workflowTemplate.name}.Sanitize()+" TEMPLATE template0"); err != nil {
		return err
	}
	workflowTemplate.created = true
	dir, err := os.MkdirTemp("", "freightctl-workflow-template-")
	if err != nil {
		return err
	}
	workflowTemplate.private = dir
	secret, err := secure.ReadSecret(adminRef, 4096)
	if err != nil {
		return err
	}
	u, err := url.Parse(string(secret.Bytes))
	secret.Close()
	if err != nil {
		return err
	}
	u.Path = "/" + workflowTemplate.name
	ref := filepath.Join(dir, "template-admin.dsn")
	if err = os.WriteFile(ref, []byte(u.String()), 0600); err != nil {
		return err
	}
	if err = store.Migrate(ctx, ref, filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		return err
	}
	conn, err := templateConnection(ctx, ref)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var tables, rls int
	if err = conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE c.relrowsecurity AND c.relforcerowsecurity) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r'`).Scan(&tables, &rls); err != nil {
		return err
	}
	if tables != 64 || rls != 63 {
		return errors.New("empty workflow template schema or RLS profile differs")
	}
	rows, err := conn.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND c.relname<>'freightctl_schema' ORDER BY c.relname`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		var count int64
		if err = conn.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{name}.Sanitize()).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("workflow template contains domain state")
		}
	}
	// The source stays inaccessible to runtime clients. PostgreSQL deliberately
	// does not copy database-level CONNECT grants to the separate clone.
	_, err = admin.Exec(ctx, "REVOKE CONNECT ON DATABASE "+pgx.Identifier{workflowTemplate.name}.Sanitize()+" FROM PUBLIC")
	return err
}

func cleanupWorkflowTemplate() error {
	if workflowTemplate.created {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		admin, err := templateConnection(ctx, workflowTemplate.adminRef)
		if err != nil {
			return err
		}
		defer admin.Close(context.Background())
		if _, err = admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{workflowTemplate.name}.Sanitize()+" WITH (FORCE)"); err != nil {
			return err
		}
	}
	if workflowTemplate.private != "" {
		return os.RemoveAll(workflowTemplate.private)
	}
	return nil
}

func TestWorkflowTemplateClonesKeepDatabasesAndRuntimeAuthoritySeparate(t *testing.T) {
	first, second := setup(t), setup(t)
	var firstDB, secondDB string
	if err := first.admin.QueryRow(first.ctx, "SELECT current_database()").Scan(&firstDB); err != nil {
		t.Fatal(err)
	}
	if err := second.admin.QueryRow(second.ctx, "SELECT current_database()").Scan(&secondDB); err != nil {
		t.Fatal(err)
	}
	if firstDB == secondDB || firstDB == workflowTemplate.name || secondDB == workflowTemplate.name {
		t.Fatal("fixture reused a database")
	}
	for _, pair := range []struct{ destination, source *fixture }{{first, second}, {second, first}} {
		var exists bool
		if err := pair.destination.admin.QueryRow(pair.destination.ctx, "SELECT EXISTS(SELECT 1 FROM files WHERE file_id=$1)", pair.source.file.ID).Scan(&exists); err != nil || exists {
			t.Fatal("domain state crossed independent clones", err)
		}
	}
	secret, err := secure.ReadSecret(first.runtimePath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(secret.Bytes))
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + workflowTemplate.name
	conn, err := pgx.Connect(first.ctx, u.String())
	if conn != nil {
		conn.Close(first.ctx)
	}
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "42501" {
		t.Fatal("runtime could connect to protected schema template", err)
	}
}
