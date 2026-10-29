//go:build integration

package assistance

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	ctx        context.Context
	admin      *pgxpool.Pool
	adminPath  string
	wf         *workflow.Service
	scope      store.Scope
	file       *store.File
	connection workflow.ConnectionView
	request    workflow.ConnectionRequest
}

func setup(t *testing.T) *fixture {
	t.Helper()
	adminRef, runtimeRef := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE")
	if adminRef == "" || runtimeRef == "" {
		t.Fatal("real PostgreSQL references required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	open := func(ref string) *pgxpool.Pool {
		t.Helper()
		secret, err := secure.ReadSecret(ref, 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Close()
		pool, err := pgxpool.New(ctx, string(secret.Bytes))
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}
	admin := open(adminRef)
	t.Cleanup(admin.Close)
	name := "freightctl_assistance_" + strings.ReplaceAll(secure.NewID(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Error(err)
		}
	})
	paths := []string{}
	for _, ref := range []string{adminRef, runtimeRef} {
		secret, err := secure.ReadSecret(ref, 4096)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(string(secret.Bytes))
		secret.Close()
		if err != nil {
			t.Fatal(err)
		}
		u.Path = "/" + name
		dest := filepath.Join(t.TempDir(), "database.dsn")
		if err = os.WriteFile(dest, []byte(u.String()), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, dest)
	}
	if err := store.Migrate(ctx, paths[0], filepath.Join(filepath.Dir(adminRef), "pg-runtime-password")); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, paths[1])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	disk, err := custody.Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disk.Close() })
	a := open(paths[0])
	t.Cleanup(a.Close)
	f := &fixture{ctx: ctx, admin: a, adminPath: paths[0], wf: &workflow.Service{Custody: &custody.Service{DB: db, Disk: disk, MaxFile: 8 << 20, MaxStored: 64 << 20}}, scope: store.Scope{Tenant: secure.NewID(), Partner: secure.NewID()}}
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err = secure.WriteToken(tokenPath); err != nil {
		t.Fatal(err)
	}
	if err = store.Provision(ctx, paths[0], f.scope.Tenant, f.scope.Partner, tokenPath); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		t.Fatal(err)
	}
	f.scope.TokenHash = secure.Digest(secret.Bytes)
	secret.Close()
	f.file, _, err = f.wf.Custody.Accept(ctx, f.scope, "source", 3, secure.Digest([]byte("abc")), bytes.NewReader([]byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	host, hostPub := filepath.Join(dir, "host"), filepath.Join(dir, "host.pub")
	client, clientPub := filepath.Join(dir, "client"), filepath.Join(dir, "client.pub")
	if err = secure.GenerateSSHHostIdentity(host, hostPub); err != nil {
		t.Fatal(err)
	}
	if err = secure.GenerateSSHHostIdentity(client, clientPub); err != nil {
		t.Fatal(err)
	}
	f.request = workflow.ConnectionRequest{Address: "127.0.0.1:9", User: "receiver", Directory: "/inbox", HostPublicFile: hostPub, KeyFile: client, KeyPublicFile: clientPub}
	registered, err := f.wf.RegisterConnection(ctx, f.scope, "register", f.request)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(registered.Resource, &f.connection); err != nil {
		t.Fatal(err)
	}
	return f
}
