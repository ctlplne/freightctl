package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ctlplne/freightctl/internal/api"
	"github.com/ctlplne/freightctl/internal/audit"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/sftpd"
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
		fmt.Println("freightctl: init | token | enroll | identity | namespace | dev-cert | serve | reconcile | audit-keygen | audit-export | ssh-host-keygen | ssh-key-enroll | ssh-key-revoke | serve-sftp | upload-create | upload-list | upload-status | upload-append | upload-complete | upload-abort | delivery-create | delivery-status | delivery-approve | delivery-cancel | delivery-work | delivery-reconcile\nConnections: connection-register | connection-status | connection-revoke\nWorkflows: workflow-validate | workflow-draft | workflow-status | workflow-diff | workflow-approve | workflow-revoke | workflow-run | workflow-run-status | workflow-work | workflow-cancel\nAssistance: ai-profile-register | ai-profile-status | ai-profile-revoke | ai-propose | ai-diagnose | ai-status | ai-approve | ai-generate | ai-adopt\nIntake: intake-policy-register | intake-policy-status | intake-policy-revoke | check-list | check-status | check-run | check-release\nScanners: scanner-register | scanner-status | scanner-revoke\nOpenPGP: pgp-key-register | pgp-key-status | pgp-key-revoke | check-signature\nRead docs/development.md. This is an unqualified local custody foundation.")
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
	defaultListen := "127.0.0.1:28446"
	if args[0] == "serve-sftp" {
		defaultListen = "127.0.0.1:28447"
	}
	listen := f.String("listen", defaultListen, "numeric loopback address")
	storage := f.String("storage", ".private/custody", "private custody directory")
	maxFile := f.Int64("max-file-bytes", 64<<20, "maximum upload bytes")
	maxStored := f.Int64("max-stored-bytes", 1<<30, "total custody quota, including retained orphans")
	reconcileBytes := f.Int64("reconcile-max-bytes", 64<<20, "maximum bytes hashed per read-only reconciliation")
	auditKey := f.String("audit-key-file", "", "protected Ed25519 audit signing identity reference")
	auditPublic := f.String("audit-public-file", ".private/audit-signing.pub", "public audit verification identity output")
	auditMaxEvents := f.Int("audit-max-events", 10000, "maximum events per evidence snapshot")
	auditMaxBytes := f.Int("audit-max-bytes", 8<<20, "maximum serialized evidence bytes before base64 encoding")
	output := f.String("output", ".private/audit-export.json", "new protected artifact output path")
	permissions := f.String("permissions", strings.Join(store.DefaultPermissions, ","), "comma-separated scoped account permissions")
	namespaceRoot := f.String("namespace-root", "/", "canonical directory mounted as this identity's virtual root")
	namespaceMax := f.Int("namespace-max-entries", 10000, "active virtual entries allowed per partner")
	requestFile := f.String("request-file", "", "bounded JSON namespace command reference")
	idempotencyKey := f.String("idempotency-key", "", "stable namespace operation key")
	uploadID := f.String("upload-id", "", "durable upload session UUID")
	uploadAfter := f.String("upload-after", "", "last upload UUID returned by the previous page")
	uploadLimit := f.Int("upload-limit", 50, "owned uploads per page, at most 100")
	uploadOffset := f.Int64("upload-offset", 0, "expected committed upload offset")
	chunkFile := f.String("chunk-file", "", "bounded chunk input file reference")
	checkpointBytes := f.Int("upload-checkpoint-bytes", 1<<20, "resumable SFTP checkpoint size, 64 KiB to 8 MiB")
	deliveryID := f.String("delivery-id", "", "durable outbound delivery UUID")
	deliveryHash := f.String("definition-hash", "", "exact reviewed delivery definition digest")
	deliveryRevision := f.Int64("expected-revision", 0, "exact reviewed delivery state revision")
	workflowID := f.String("workflow-id", "", "immutable workflow family UUID")
	connectionID := f.String("connection-id", "", "registered connection family UUID")
	resourceVersion := f.Int("version", 1, "exact workflow or connection version")
	againstVersion := f.Int("against-version", 0, "previous workflow version to compare")
	runID := f.String("run-id", "", "durable workflow run UUID")
	checkFileID := f.String("file-id", "", "exact immutable file UUID for intake checks or release")
	checkAfter := f.String("check-after", "", "last check file UUID returned by the previous page")
	checkLimit := f.Int("check-limit", 50, "private intake check summaries per page, at most 100")
	pgpKeyID := f.String("pgp-key-id", "", "exact registered OpenPGP key family UUID")
	scannerID := f.String("scanner-id", "", "exact registered local scanner family UUID")
	pgpPublicFile := f.String("pgp-public-file", "", "protected public-key input reference; private packets are refused")
	signatureFile := f.String("signature-file", "", "protected detached binary-signature input reference")
	dataSHA := f.String("data-sha256", "", "exact accepted data SHA-256 bound by the signature attachment")
	policyHash := f.String("policy-hash", "", "exact current intake policy hash bound by the signature attachment")
	aiProfileID := f.String("ai-profile-id", "", "explicit administrator-registered AI profile UUID")
	aiJobID := f.String("ai-job-id", "", "scoped assistance context/job UUID")
	contextHash := f.String("context-hash", "", "exact reviewed disclosure context SHA-256")
	aiEnabled := f.Bool("ai-enabled", false, "opt in to requests to explicitly registered inference endpoints; disabled by default")
	browserSessionSeconds := f.Int("browser-session-seconds", 600, "browser session lifetime in seconds, 1 to 600; new login required after expiry")
	sshHost := f.String("ssh-host-key-file", ".private/ssh-host.key", "protected Ed25519 SSH host identity reference")
	sshPublic := f.String("ssh-public-file", "", "public SSH key reference; host-keygen defaults to host reference plus .pub")
	sshKeyID := f.String("ssh-key-id", "", "registered key UUID to revoke")
	sshConnections := f.Int("ssh-max-connections", 16, "maximum concurrent SSH connections")
	sshWriters := f.Int("ssh-max-writers", 2, "maximum open SFTP writers in the initial serialized profile")
	sshSession := f.Duration("ssh-session-limit", 5*time.Minute, "absolute SSH connection lifetime")
	sshIdle := f.Duration("ssh-idle-limit", 30*time.Second, "maximum SSH inactivity")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] == "serve" || args[0] == "serve-sftp" || strings.HasPrefix(args[0], "upload-") {
		if *checkpointBytes < int(custody.MinUploadChunk) || *checkpointBytes > int(custody.MaxUploadChunk) || *maxFile < 1 || *maxFile > 1<<30 || *maxStored < *maxFile || *namespaceMax < 1 {
			return errors.New("invalid upload checkpoint, file, storage or namespace budget")
		}
	}
	ctx := context.Background()
	if args[0] == "serve" && (*browserSessionSeconds < 1 || *browserSessionSeconds > 600) {
		return errors.New("browser session lifetime must be 1 to 600 seconds")
	}
	switch args[0] {
	case "scanner-register", "scanner-status", "scanner-revoke":
		return runScanner(ctx, args[0], *dsn, *token, *tenant, *partner, *requestFile, *idempotencyKey, *scannerID, *deliveryHash, *resourceVersion, *deliveryRevision)
	case "pgp-key-register", "pgp-key-status", "pgp-key-revoke", "check-signature":
		return runPGP(ctx, args[0], pgpOptions{DSN: *dsn, Token: *token, Tenant: *tenant, Partner: *partner, Storage: *storage, Input: *requestFile, Key: *idempotencyKey, KeyID: *pgpKeyID, FileID: *checkFileID, PublicFile: *pgpPublicFile, SignatureFile: *signatureFile, DataSHA: *dataSHA, PolicyHash: *policyHash, DefinitionHash: *deliveryHash, Version: *resourceVersion, Revision: *deliveryRevision, MaxStored: *maxStored})
	case "intake-policy-register", "intake-policy-status", "intake-policy-revoke", "check-list", "check-status", "check-run", "check-release":
		return runChecks(ctx, args[0], *dsn, *token, *tenant, *partner, *storage, *requestFile, *idempotencyKey, *checkFileID, *checkAfter, *checkLimit, *namespaceMax)
	case "ai-profile-register", "ai-profile-status", "ai-profile-revoke", "ai-propose", "ai-diagnose", "ai-status", "ai-approve", "ai-generate", "ai-adopt":
		return runAssistance(ctx, args[0], *dsn, *token, *tenant, *partner, *requestFile, *idempotencyKey, *aiProfileID, *aiJobID, *contextHash, *deliveryHash, *resourceVersion, *deliveryRevision, *aiEnabled)
	case "connection-register", "connection-status", "connection-revoke", "workflow-validate", "workflow-draft", "workflow-status", "workflow-approve", "workflow-revoke", "workflow-run", "workflow-run-status", "workflow-work", "workflow-diff", "workflow-cancel":
		return runWorkflow(ctx, args[0], *dsn, *token, *tenant, *partner, *storage, *requestFile, *idempotencyKey, *workflowID, *connectionID, *runID, *deliveryHash, *resourceVersion, *againstVersion, *deliveryRevision, *maxFile, *maxStored)
	case "delivery-create", "delivery-status", "delivery-approve", "delivery-cancel", "delivery-work", "delivery-reconcile":
		return runDelivery(ctx, args[0], *dsn, *token, *tenant, *partner, *storage, *requestFile, *idempotencyKey, *deliveryID, *deliveryHash, *deliveryRevision, *maxFile, *maxStored)
	case "init":
		return store.Migrate(ctx, *admin, *password)
	case "token":
		return secure.WriteToken(*token)
	case "enroll":
		selected := []string{}
		if *permissions != "" {
			selected = strings.Split(*permissions, ",")
		}
		return store.ProvisionPolicy(ctx, *admin, *tenant, *partner, *token, selected, *namespaceRoot)
	case "upload-create", "upload-list", "upload-status", "upload-append", "upload-complete", "upload-abort":
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
		service := &custody.Service{DB: db, MaxFile: *maxFile, MaxStored: *maxStored, NamespaceMaxEntries: *namespaceMax, UploadCheckpointBytes: *checkpointBytes}

		if args[0] != "upload-abort" {
			var disk *custody.Disk
			if args[0] == "upload-create" {
				disk, err = custody.Open(*storage)
			} else {
				disk, err = custody.OpenExisting(*storage)
			}
			if err != nil {
				return err
			}
			defer disk.Close()
			service.Disk = disk
		}
		if args[0] == "upload-status" {
			result, err := service.UploadStatus(ctx, scope, *uploadID)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if args[0] == "upload-list" {
			result, err := service.ListUploads(ctx, scope, *uploadAfter, *uploadLimit)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(result)
		}

		var result *custody.UploadResult
		switch args[0] {
		case "upload-create":
			input, err := os.Open(*requestFile)
			if err != nil {
				return errors.New("cannot open upload request reference")
			}
			defer input.Close()
			st, err := input.Stat()
			if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 {
				return errors.New("upload request must be bounded regular JSON")
			}
			decoder := json.NewDecoder(io.LimitReader(input, 16<<10))
			decoder.DisallowUnknownFields()
			var request custody.CreateUpload
			if err = decoder.Decode(&request); err != nil {
				return errors.New("invalid upload request JSON")
			}
			var extra any
			if err = decoder.Decode(&extra); err != io.EOF {
				return errors.New("upload request has trailing data")
			}
			result, err = service.CreateUpload(ctx, scope, *idempotencyKey, request)
		case "upload-append":
			input, openErr := os.Open(*chunkFile)
			if openErr != nil {
				return errors.New("cannot open chunk reference")
			}
			defer input.Close()
			st, statErr := input.Stat()
			if statErr != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > custody.MaxUploadChunk {
				return errors.New("chunk must be a regular file of 1 byte to 8 MiB")
			}
			h := secure.NewDigest()
			n, copyErr := io.CopyBuffer(h, io.LimitReader(input, custody.MaxUploadChunk+1), make([]byte, 32<<10))
			if copyErr != nil || n != st.Size() {
				return custody.ErrIntegrity
			}
			if _, err = input.Seek(0, io.SeekStart); err != nil {
				return err
			}
			result, err = service.AppendUpload(ctx, scope, *uploadID, *idempotencyKey, *uploadOffset, n, fmt.Sprintf("%x", h.Sum(nil)), input)
		case "upload-complete":
			result, err = service.CompleteUpload(ctx, scope, *uploadID, *idempotencyKey)
		case "upload-abort":
			result, err = service.AbortUpload(ctx, scope, *uploadID, *idempotencyKey)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "identity", "namespace":
		if args[0] == "namespace" && *namespaceMax < 1 {
			return errors.New("namespace entry budget must be positive")
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
		if args[0] == "identity" {
			info, err := db.Identity(ctx, scope)
			if err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(info)
		}
		input, err := os.Open(*requestFile)
		if err != nil {
			return errors.New("cannot open command reference")
		}
		defer input.Close()
		st, err := input.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<10 {
			return errors.New("command must be a bounded regular JSON file")
		}
		decoder := json.NewDecoder(io.LimitReader(input, 16<<10))
		decoder.DisallowUnknownFields()
		var command store.PathCommand
		if err = decoder.Decode(&command); err != nil {
			return errors.New("invalid namespace command JSON")
		}
		var extra any
		if err = decoder.Decode(&extra); err != io.EOF {
			return errors.New("namespace command contains trailing data")
		}
		service := &custody.Service{DB: db, NamespaceMaxEntries: *namespaceMax, UploadCheckpointBytes: *checkpointBytes}
		if command.Operation == "publish" {
			disk, err := custody.OpenExisting(*storage)
			if err != nil {
				return err
			}
			defer disk.Close()
			service.Disk = disk
		}
		result, err := service.PathCommand(ctx, scope, *idempotencyKey, command)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "dev-cert":
		return secure.DevCertificate(*cert, *key)
	case "audit-keygen":
		path := *auditKey
		if path == "" {
			path = ".private/audit-signing.key"
		}
		return secure.GenerateAuditIdentity(path, *auditPublic)
	case "ssh-host-keygen":
		public := *sshPublic
		if public == "" {
			public = *sshHost + ".pub"
		}
		return secure.GenerateSSHHostIdentity(*sshHost, public)
	case "ssh-key-enroll", "ssh-key-revoke":
		operation, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var public secure.SSHPublic
		var err error
		revoke := ""
		if args[0] == "ssh-key-enroll" {
			if *sshPublic == "" {
				return errors.New("SSH enrollment requires an explicit public key reference")
			}
			public, err = secure.ReadSSHPublic(*sshPublic)
			if err != nil {
				return err
			}
		} else {
			revoke = *sshKeyID
			if !store.ValidID(revoke) {
				return errors.New("SSH revocation requires a key UUID")
			}
		}
		result, err := store.ManageSSHKey(operation, *admin, *token, *tenant, *partner, public, revoke)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
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
	case "serve-sftp":
		host, _, err := net.SplitHostPort(*listen)
		if err != nil {
			return errors.New("invalid listen address")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("development SFTP profile requires numeric loopback")
		}
		if *maxFile < 1 || *maxFile > 1<<30 || *maxStored < *maxFile || *namespaceMax < 1 {
			return errors.New("invalid file, storage or namespace budget")
		}
		if *sshSession <= 0 || *sshSession > time.Hour || *sshIdle <= 0 || *sshIdle > *sshSession {
			return errors.New("SSH time budgets must be positive, idle within session, session at most one hour")
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
		service, err := sftpd.New(&custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, NamespaceMaxEntries: *namespaceMax, UploadCheckpointBytes: *checkpointBytes}, *sshWriters)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return errors.New("cannot open SFTP listener")
		}
		defer listener.Close()
		stop, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		fmt.Println("freightctl SFTP custody listening on", *listen, "(integrity-only; not production qualified)")
		return secure.ServeSFTP(stop, listener, secure.SSHOptions{HostKeyFile: *sshHost, MaxConnections: *sshConnections, SessionLimit: *sshSession, IdleLimit: *sshIdle}, db.AllowSSHKey, service.Session)
	case "serve":
		if *namespaceMax < 1 {
			return errors.New("namespace entry budget must be positive")
		}
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
		server := &http.Server{Addr: *listen, Handler: api.NewWithBrowserLifetime(&custody.Service{DB: db, Disk: disk, MaxFile: *maxFile, MaxStored: *maxStored, ReconcileMaxBytes: *reconcileBytes, NamespaceMaxEntries: *namespaceMax, UploadCheckpointBytes: *checkpointBytes}, audits, *aiEnabled, time.Duration(*browserSessionSeconds)*time.Second), TLSConfig: secure.TLSConfig(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 90 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		stop, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer cancel()
		go func() {
			<-stop.Done()
			shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = server.Shutdown(shutdown)
		}()
		fmt.Println("freightctl HTTPS custody listening on", *listen, "(selected intake policy controls acceptance; development profile)")
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
