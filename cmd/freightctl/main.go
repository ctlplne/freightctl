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
	"syscall"
	"time"

	"github.com/ctlplne/freightctl/internal/api"
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
		fmt.Println("freightctl: init | token | enroll | dev-cert | serve | reconcile\nRead docs/development.md. This is an unqualified local custody foundation.")
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
		server := &http.Server{Addr: *listen, Handler: api.New(&custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, ReconcileMaxBytes: *reconcileBytes}), TLSConfig: secure.TLSConfig(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
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
