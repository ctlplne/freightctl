package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ctlplne/freightctl/internal/api"
	"github.com/ctlplne/freightctl/internal/audit"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "freightctl:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Println("freightctl: init | token | enroll | dev-cert | serve | reconcile | audit-keygen | audit-export\nRead docs/development.md. This is an unqualified local custody foundation.")
		return nil
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	admin := f.String("admin-dsn-file", ".private/pg-admin.dsn", "protected admin database reference")
	dsn := f.String("dsn-file", ".private/pg-runtime.dsn", "protected runtime database reference")
	password := f.String("runtime-password-file", ".private/pg-runtime-password", "protected runtime role password reference")
	token := f.String("token-file", ".private/partner.token", "protected token reference")
	tenant := f.String("tenant", "", "tenant UUID")
	partner := f.String("partner", "", "partner UUID")
	cert := f.String("cert", ".private/localhost.crt", "TLS certificate path")
	key := f.String("key", ".private/localhost.key", "TLS key reference")
	listen := f.String("listen", "127.0.0.1:28446", "HTTPS loopback address")
	storage := f.String("storage", ".private/custody", "private custody directory")
	maxFile := f.Int64("max-file-bytes", 64<<20, "maximum upload bytes")
	maxStored := f.Int64("max-stored-bytes", 1<<30, "total custody quota, including retained orphans")
	reconcileBytes := f.Int64("reconcile-max-bytes", 64<<20, "maximum bytes hashed per read-only reconciliation")
	auditKey := f.String("audit-key-file", "", "protected Ed25519 audit signing identity reference")
	auditPublic := f.String("audit-public-file", ".private/audit-signing.pub", "public audit verification identity output")
	auditMaxEvents := f.Int("audit-max-events", 10000, "maximum events per evidence snapshot")
	auditMaxBytes := f.Int("audit-max-bytes", 8<<20, "maximum serialized evidence bytes before base64 encoding")
	output := f.String("output", ".private/audit-export.json", "new protected artifact output path")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	ctx := context.Background()
	switch args[0] {
	case "init":
		return store.Migrate(ctx, *admin, *password)
	case "token":
		return secure.WriteToken(*token)
	case "enroll":
		return store.Provision(ctx, *admin, *tenant, *partner, *token)
	case "dev-cert":
		return secure.DevCertificate(*cert, *key)
	case "audit-keygen":
		path := *auditKey
		if path == "" {
			path = ".private/audit-signing.key"
		}
		return secure.GenerateAuditIdentity(path, *auditPublic)
	case "audit-export":
		if _, err := os.Lstat(*output); !os.IsNotExist(err) {
			return errors.New("artifact output must be a new file")
		}
		secret, err := secure.ReadSecret(*token, 64)
		if err != nil {
			return err
		}
		scope := store.Scope{Tenant: *tenant, Partner: *partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		db, err := store.Open(ctx, *dsn)
		if err != nil {
			return err
		}
		defer db.Pool.Close()
		envelope, err := (&audit.Service{DB: db, KeyFile: *auditKey, MaxEvents: *auditMaxEvents, MaxBytes: *auditMaxBytes}).Export(ctx, scope)
		if err != nil {
			return err
		}
		return writeArtifact(*output, envelope)
	case "reconcile":
		secret, err := secure.ReadSecret(*token, 64)
		if err != nil {
			return err
		}
		scope := store.Scope{Tenant: *tenant, Partner: *partner, TokenHash: secure.Digest(secret.Bytes)}
		secret.Close()
		db, err := store.Open(ctx, *dsn)
		if err != nil {
			return err
		}
		defer db.Pool.Close()
		disk, err := custody.OpenExisting(*storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		service := &custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, ReconcileMaxBytes: *reconcileBytes}
		report, err := service.Reconcile(ctx, scope)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	case "serve":
		host, _, err := net.SplitHostPort(*listen)
		if err != nil {
			return errors.New("invalid listen address")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("initial development profile requires a numeric loopback listen address")
		}
		if *maxFile < 1 || *maxFile > 1<<30 || *maxStored < *maxFile {
			return errors.New("file limit must be 1 byte to 1 GiB; custody quota must cover one file")
		}
		db, err := store.Open(ctx, *dsn)
		if err != nil {
			return err
		}
		defer db.Pool.Close()
		disk, err := custody.Open(*storage)
		if err != nil {
			return err
		}
		defer disk.Close()
		secret, err := secure.ReadSecret(*key, 16384)
		if err != nil {
			return err
		}
		secret.Close()
		audits := &audit.Service{DB: db, KeyFile: *auditKey, MaxEvents: *auditMaxEvents, MaxBytes: *auditMaxBytes}
		server := &http.Server{Addr: *listen, Handler: api.New(&custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, ReconcileMaxBytes: *reconcileBytes}, audits), TLSConfig: secure.TLSConfig(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		stop, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		go func() {
			<-stop.Done()
			shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = server.Shutdown(shutdown)
		}()
		fmt.Println("freightctl HTTPS custody listening on", *listen, "(integrity-only; not production qualified)")
		err = server.ListenAndServeTLS(*cert, *key)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("HTTPS listener failed; verify address and TLS references")
	default:
		return errors.New("unknown command; use --help")
	}
}

func writeArtifact(path string, value any) error {
	directory := filepath.Dir(path)
	f, err := os.CreateTemp(directory, ".freightctl-artifact-*")
	if err != nil {
		return errors.New("cannot stage artifact in output directory")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = json.NewEncoder(f).Encode(value); err != nil {
		return err
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return errors.New("cannot publish new artifact without overwriting; verify output path and filesystem hard-link support")
	}
	if err = os.Remove(f.Name()); err != nil {
		return err
	}
	d, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
