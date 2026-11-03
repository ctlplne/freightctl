//go:build integration

package custody_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/ftpsd"
	"github.com/ctlplne/freightctl/internal/store"
)

type ftpsFixture struct {
	f                        *fixture
	url, config, cert, token string
}

func startFTPS(t *testing.T, implicit bool) *ftpsFixture {
	t.Helper()
	f := setup(t)
	f.service.NamespaceMaxEntries = 10000
	dir := t.TempDir()
	token := filepath.Join(dir, "token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	admin := os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE")
	if err := store.Provision(f.ctx, admin, f.a.Tenant, f.a.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	f.a.TokenHash = secure.Digest(secret.Bytes)
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := secure.DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	identity, err := secure.LoadFTPSIdentity(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ftpsd.New(f.service, ftpsd.Options{Identity: identity, Implicit: implicit, EnableActive: true, MaxConnections: 4, MaxWriters: 1, ListLimit: 100, SessionLimit: 30 * time.Second, IdleLimit: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("FTPS session cleanup exceeded deadline")
		}
	})
	config := filepath.Join(dir, "curl.conf")
	// Credentials live in one owner-only reference, never in argv or output.
	user := f.a.Tenant + "/" + f.a.Partner + ":" + string(secret.Bytes)
	secret.Close()
	text := "user = " + strconv.Quote(user) + "\ncacert = " + strconv.Quote(cert) + "\nssl-reqd\ntls-max = \"1.3\"\nconnect-timeout = 3\nmax-time = 10\nnoproxy = \"*\"\nproto = \"=ftp,ftps\"\nsilent\nshow-error\n"
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	scheme := "ftp"
	if implicit {
		scheme = "ftps"
	}
	return &ftpsFixture{f: f, url: scheme + "://" + l.Addr().String(), config: config, cert: cert, token: token}
}

func (f *ftpsFixture) curl(t *testing.T, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.f.ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "curl", append([]string{"-q", "--verbose", "--config", f.config}, args...)...)
	var out, diagnostic bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	err := cmd.Run()
	if err != nil {
		// Keep server replies for first-failure diagnosis. Never print curl's
		// outgoing USER/PASS lines or its credential-bearing debug context.
		var replies []string
		for _, line := range strings.Split(diagnostic.String(), "\n") {
			if strings.HasPrefix(line, "< ") {
				replies = append(replies, line)
			}
		}
		t.Fatalf("stock curl failed: %v; server replies:\n%s", err, strings.Join(replies, "\n"))
	}
	return out.Bytes()
}

func TestFTPSStockCurlExplicitImplicitAndActiveCustody(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			dir := t.TempDir()
			payload := bytes.Repeat([]byte("opaque\x00bytes\r\nline\n"), 4096)
			input := filepath.Join(dir, "input")
			if err := os.WriteFile(input, payload, 0600); err != nil {
				t.Fatal(err)
			}
			// Apple's LibreSSL curl negotiates TLS1.3 but cannot set that
			// explicit minimum knob. The server's fixed TLS1.3 floor enforces
			// it for every handshake; a TLS1.2-only client must fail here.
			oldTLS := exec.CommandContext(f.f.ctx, "curl", "-q", "--config", f.config, "--tls-max", "1.2", f.url+"/")
			if err := oldTLS.Run(); err == nil {
				t.Fatal("FTPS accepted a TLS1.2-only client")
			}
			f.curl(t, "--upload-file", input, f.url+"/file.bin")
			entry, err := f.f.service.StatPath(f.f.ctx, f.f.a, "/file.bin")
			if err != nil || entry.Size != int64(len(payload)) {
				t.Fatal("upload was not durably published", err)
			}
			if got := f.curl(t, f.url+"/file.bin"); !bytes.Equal(got, payload) {
				t.Fatal("passive download changed opaque bytes")
			}
			if got := f.curl(t, "--disable-epsv", f.url+"/file.bin"); !bytes.Equal(got, payload) {
				t.Fatal("PASV download changed bytes")
			}
			if got := f.curl(t, "--ftp-port", "-", f.url+"/file.bin"); !bytes.Equal(got, payload) {
				t.Fatal("active download changed bytes")
			}
			f.curl(t, "--ftp-port", "-", "--upload-file", input, f.url+"/active.bin")
			if got := f.curl(t, f.url+"/active.bin"); !bytes.Equal(got, payload) {
				t.Fatal("active upload changed bytes")
			}
			listing := string(f.curl(t, "--list-only", f.url+"/"))
			if !strings.Contains(listing, "file.bin") || !strings.Contains(listing, "active.bin") {
				t.Fatal("published paths absent from listing")
			}
			f.curl(t, "--quote", "MKD inbox", "--list-only", f.url+"/")
			f.curl(t, "--quote", "RNFR file.bin", "--quote", "RNTO renamed.bin", f.url+"/renamed.bin")
			if got := f.curl(t, f.url+"/renamed.bin"); !bytes.Equal(got, payload) {
				t.Fatal("rename changed revision bytes")
			}
			f.curl(t, "--quote", "DELE active.bin", "--quote", "RMD inbox", "--list-only", f.url+"/")
			var sessions int
			if err := f.f.admin.QueryRow(f.f.ctx, `SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND kind='ProtocolSessionStarted' AND payload->>'protocol'=$3`, f.f.a.Tenant, f.f.a.Partner, map[bool]string{false: "ftps-explicit", true: "ftps-implicit"}[implicit]).Scan(&sessions); err != nil || sessions < 10 {
				t.Fatal("missing immutable protocol session audit", sessions, err)
			}
			if _, err := f.f.service.StatPath(f.f.ctx, f.f.b, "/renamed.bin"); err == nil {
				t.Fatal("another partner read an FTPS path")
			}
			t.Log(fmt.Sprintf("stock curl preserved %d bytes through protected passive/active transfers and namespace commands", len(payload)))
		})
	}
}

func TestFTPSNativeTLSClientProtocolAndInterruption(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			u, err := url.Parse(f.url)
			if err != nil {
				t.Fatal(err)
			}
			_, port, err := net.SplitHostPort(u.Host)
			if err != nil {
				t.Fatal(err)
			}
			number, err := strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			secret, err := secure.ReadSecret(f.token, 64)
			if err != nil {
				t.Fatal(err)
			}
			settings := map[string]any{"port": number, "implicit": implicit, "certificate": f.cert, "username": f.f.a.Tenant + "/" + f.f.a.Partner, "password": string(secret.Bytes), "other_partner_identity": f.f.b.Tenant + "/" + f.f.b.Partner, "other_tenant_identity": f.f.c.Tenant + "/" + f.f.c.Partner}
			secret.Close()
			ref := filepath.Join(t.TempDir(), "probe.json")
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ref, data, 0600); err != nil {
				t.Fatal(err)
			}
			probe := exec.CommandContext(f.f.ctx, "python3", filepath.Join("..", "..", "scripts", "ftps-probe.py"), "--reference", ref)
			out, err := probe.CombinedOutput()
			if err != nil {
				t.Fatalf("native TLS client probe failed: %v; %s", err, out)
			}
			var report struct {
				State     string
				CaseCount int  `json:"case_count"`
				Resumed   bool `json:"all_ordinary_data_resumed"`
			}
			if err := json.Unmarshal(out, &report); err != nil || report.State != "passed" || report.CaseCount != 15 || !report.Resumed {
				t.Fatalf("incomplete native TLS probe: %v; %s", err, out)
			}
			t.Logf("native TLS1.3 FTP stand-in passed15 protocol/identity/interruption cases; stock-client qualification remains separate")
		})
	}
}

func TestFTPSStockLFTPCustody(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := startFTPS(t, implicit)
			u, err := url.Parse(f.url)
			if err != nil {
				t.Fatal(err)
			}
			_, port, err := net.SplitHostPort(u.Host)
			if err != nil {
				t.Fatal(err)
			}
			number, err := strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			source := filepath.Join(dir, "payload")
			payload := bytes.Repeat([]byte("stock lftp\x00opaque\r\nbytes\n"), 2048)
			if err := os.WriteFile(source, payload, 0600); err != nil {
				t.Fatal(err)
			}
			secret, err := secure.ReadSecret(f.token, 64)
			if err != nil {
				t.Fatal(err)
			}
			settings := map[string]any{"port": number, "implicit": implicit, "certificate": f.cert, "source": source, "username": f.f.a.Tenant + "/" + f.f.a.Partner, "password": string(secret.Bytes)}
			secret.Close()
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			ref := filepath.Join(dir, "probe.json")
			if err := os.WriteFile(ref, data, 0600); err != nil {
				t.Fatal(err)
			}
			probe := exec.CommandContext(f.f.ctx, "python3", filepath.Join("..", "..", "scripts", "lftp-probe.py"), "--reference", ref)
			out, err := probe.CombinedOutput()
			if err != nil {
				t.Fatalf("stock lftp probe failed: %v; %s", err, out)
			}
			var report struct {
				State     string
				CaseCount int  `json:"case_count"`
				Stock     bool `json:"stock_client_qualification"`
			}
			if err := json.Unmarshal(out, &report); err != nil || report.State != "passed" || report.CaseCount != 4 || !report.Stock {
				t.Fatalf("incomplete stock lftp probe: %v; %s", err, out)
			}
			t.Logf("stock lftp preserved %d opaque bytes through EPSV/PASV/active transfers and namespace commands", len(payload))
		})
	}
}
