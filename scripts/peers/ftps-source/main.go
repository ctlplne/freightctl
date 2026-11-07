// This qualification-only source runs on a disposable GitHub Linux runner.
// It uses the ordinary custody/FTPS implementation and counts control accepts;
// it adds no product API, protocol command or authentication exception.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"syscall"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/ftpsd"
)

var errFixture = errors.New("FTPS source fixture contract failed")
var databasePattern = regexp.MustCompile(`^freightctl_ftps_[0-9a-f]{32}$`)
var fixturePattern = regexp.MustCompile(`^ftps-[0-9a-f]{32}$`)

type configuration struct {
	Database    string `json:"database"`
	DSN         string `json:"dsn_file"`
	Storage     string `json:"storage"`
	Certificate string `json:"certificate"`
	Key         string `json:"key"`
	Mode        string `json:"mode"`
}

func decodeConfiguration(raw []byte) (*configuration, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return nil, errFixture
	}
	values := map[string]string{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, errFixture
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errFixture
		}
		switch name {
		case "database", "dsn_file", "storage", "certificate", "key", "mode":
		default:
			return nil, errFixture
		}
		token, err := decoder.Token()
		value, ok := token.(string)
		if err != nil || !ok {
			return nil, errFixture
		}
		values[name] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || len(values) != 6 {
		return nil, errFixture
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errFixture
	}
	return &configuration{Database: values["database"], DSN: values["dsn_file"], Storage: values["storage"], Certificate: values["certificate"], Key: values["key"], Mode: values["mode"]}, nil
}

type snapshot struct {
	Schema    int    `json:"schema_version"`
	Kind      string `json:"kind"`
	Mode      string `json:"mode"`
	Port      int    `json:"port"`
	Accepted  int    `json:"accepted_connections"`
	Exhausted bool   `json:"budget_exhausted"`
	Stopped   bool   `json:"stopped"`
}

type witness struct {
	mu    sync.Mutex
	path  string
	value snapshot
}

func (w *witness) save() error {
	raw, err := json.Marshal(w.value)
	if err != nil {
		return errFixture
	}
	temporary, err := os.CreateTemp(filepath.Dir(w.path), ".counter-*")
	if err != nil {
		return errFixture
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err = temporary.Write(append(raw, '\n')); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil || closeErr != nil || os.Rename(name, w.path) != nil {
		return errFixture
	}
	return nil
}

func (w *witness) accepted() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.value.Accepted < 17 {
		w.value.Accepted++
	}
	if w.value.Accepted > 16 {
		w.value.Exhausted = true
	}
	if err := w.save(); err != nil {
		return err
	}
	if w.value.Exhausted {
		return errFixture
	}
	return nil
}

type witnessedListener struct {
	*net.TCPListener
	witness *witness
	once    sync.Once
	err     error
}

func (l *witnessedListener) Accept() (net.Conn, error) {
	connection, err := l.TCPListener.Accept()
	if err != nil {
		return nil, err
	}
	if err = l.witness.accepted(); err != nil {
		connection.Close()
		return nil, err
	}
	return connection, nil
}

func (l *witnessedListener) Close() error {
	l.once.Do(func() {
		// Wake the ordinary Go accept loop, then drain queued kernel accepts
		// before closing. A pending connection cannot hide behind a zero
		// metadata snapshot. The native adapter never serves drained peers.
		_ = l.SetDeadline(time.Now())
		l.err = drainPending(l.TCPListener, l.witness.accepted)
		if err := l.TCPListener.Close(); l.err == nil {
			l.err = err
		}
	})
	return l.err
}

func readConfiguration(root, path string) (*configuration, string, error) {
	path, err := filepath.Abs(path)
	if err != nil || filepath.Base(path) != "config.json" {
		return nil, "", errFixture
	}
	directory := filepath.Dir(path)
	estate := filepath.Dir(directory)
	if !fixturePattern.MatchString(filepath.Base(estate)) || filepath.Dir(estate) != filepath.Join(root, ".private") || (filepath.Base(directory) != "source-helper-explicit" && filepath.Base(directory) != "source-helper-implicit") {
		return nil, "", errFixture
	}
	for _, p := range []string{root, filepath.Dir(estate), estate, directory, path} {
		st, err := os.Lstat(p)
		if err != nil || st.Mode()&os.ModeSymlink != 0 || (p != root && st.Mode().Perm()&0077 != 0) {
			return nil, "", errFixture
		}
	}
	secret, err := secure.ReadSecret(path, 8192)
	if err != nil {
		return nil, "", errFixture
	}
	defer secret.Close()
	config, err := decodeConfiguration(secret.Bytes)
	if err != nil || !databasePattern.MatchString(config.Database) || (config.Mode != "explicit" && config.Mode != "implicit") || filepath.Base(directory) != "source-helper-"+config.Mode {
		return nil, "", errFixture
	}
	if config.DSN != filepath.Join(estate, "pg-runtime.dsn") || config.Storage != filepath.Join(estate, "custody") || config.Certificate != filepath.Join(estate, "cert.pem") || config.Key != filepath.Join(estate, "key.pem") {
		return nil, "", errFixture
	}
	return config, directory, nil
}

func run() error {
	root, err := os.Getwd()
	if err != nil || runtime.GOOS != "linux" || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("GITHUB_WORKSPACE") != root || len(os.Args) != 2 {
		return errFixture
	}
	config, directory, err := readConfiguration(root, os.Args[1])
	if err != nil {
		return err
	}
	ctx, cancel := sourceRuntimeContext(context.Background())
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	identity, err := secure.LoadFTPSIdentity(config.Certificate, config.Key)
	if err != nil {
		return errFixture
	}
	db, err := openSourceDatabase(ctx, config)
	if err != nil {
		return sourceDatabaseFailure
	}
	defer db.Pool.Close()
	disk, err := custody.OpenExisting(config.Storage)
	if err != nil {
		return errFixture
	}
	defer disk.Close()
	server, err := ftpsd.New(&custody.Service{DB: db, Disk: disk, MaxFile: 1 << 20, MaxStored: 8 << 20, NamespaceMaxEntries: 100}, ftpsd.Options{Identity: identity, Implicit: config.Mode == "implicit", MaxConnections: 4, MaxWriters: 1, ListLimit: 100, SessionLimit: 30 * time.Second, IdleLimit: 5 * time.Second})
	if err != nil {
		return errFixture
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		return errFixture
	}
	w := &witness{path: filepath.Join(directory, "counter.json"), value: snapshot{Schema: 1, Kind: "freightctl-ftps-source-witness-v1", Mode: config.Mode, Port: listener.Addr().(*net.TCPAddr).Port}}
	if _, err := os.Lstat(w.path); !errors.Is(err, os.ErrNotExist) {
		listener.Close()
		return errFixture
	}
	if err = w.save(); err != nil {
		listener.Close()
		return err
	}
	observed := &witnessedListener{TCPListener: listener, witness: w}
	err = server.Serve(ctx, observed)
	closeErr := observed.Close()
	w.mu.Lock()
	w.value.Stopped = true
	saved := w.save()
	exhausted := w.value.Exhausted
	w.mu.Unlock()
	return sourceShutdownFailure(err, closeErr, saved, exhausted, ctx.Err())
}

func main() {
	if err := run(); err != nil {
		// Exception text may contain private references; only this fixed label
		// leaves the fixture. The caller retains private process evidence.
		_, _ = os.Stderr.Write(sourceFailureDiagnostic(err))
		_, _ = os.Stderr.WriteString("freightctl: FTPS source fixture failed\n")
		os.Exit(1)
	}
}
