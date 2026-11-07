package ftpsclient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

type fixture struct {
	mu                sync.Mutex
	d                 secure.FTPSDestination
	identity          *secure.FTPSIdentity
	listener          net.Listener
	control           net.Conn
	passive           net.Listener
	data              net.Conn
	done              chan struct{}
	files             map[string][]byte
	verbs             []string
	resumed           int
	pasv, drop, fresh bool
	unclean           bool
	banner            string
	reportedSize      *int64
	afterRetrieve     func()
}

func newFixture(t *testing.T, implicit bool) *fixture {
	t.Helper()
	dir := t.TempDir()
	cert, key, pw := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "password")
	if err := secure.DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	writeCredentialFixture(t, pw, []byte("fixture-password"))
	identity, err := secure.LoadFTPSIdentity(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := os.ReadFile(cert)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{identity: identity, listener: l, done: make(chan struct{}), files: map[string][]byte{}, d: secure.FTPSDestination{Address: l.Addr().String(), ServerName: "localhost", User: "fixture", Mode: "explicit", CAFile: cert, CASHA256: secure.Digest(pem), PasswordFile: pw, PasswordSHA256: secure.Digest([]byte("fixture-password"))}}
	if implicit {
		f.d.Mode = "implicit"
	}
	t.Cleanup(func() {
		f.mu.Lock()
		f.listener.Close()
		if f.control != nil {
			f.control.Close()
		}
		if f.passive != nil {
			f.passive.Close()
		}
		if f.data != nil {
			f.data.Close()
		}
		f.mu.Unlock()
		select {
		case <-f.done:
		case <-time.After(4 * time.Second):
			t.Error("bounded fixture did not stop")
		}
	})
	return f
}
func (f *fixture) start() { go func() { defer close(f.done); f.serve() }() }
func (f *fixture) serve() {
	raw, err := f.listener.Accept()
	if err != nil {
		return
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(8 * time.Second))
	f.mu.Lock()
	f.control = raw
	f.mu.Unlock()
	binding, err := f.identity.BindFTPSControl(raw.LocalAddr())
	if err != nil {
		return
	}
	defer binding.Close()
	var control net.Conn = raw
	if f.d.Mode == "implicit" {
		control = binding.FTPSImplicitServer(raw)
	}
	write := func(text string) bool { _, e := io.WriteString(control, text+"\r\n"); return e == nil }
	if f.banner != "" {
		write(f.banner)
		return
	}
	if !write("220 fixture") {
		return
	}
	reader := bufio.NewReader(control)
	var passive net.Listener
	var rest int64
	var from string
	defer func() {
		if passive != nil {
			passive.Close()
		}
	}()
	for {
		line, e := reader.ReadString('\n')
		if e != nil {
			return
		}
		if len(line) > 4096 {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		verb, arg, _ := strings.Cut(line, " ")
		f.mu.Lock()
		f.verbs = append(f.verbs, verb)
		f.mu.Unlock()
		switch verb {
		case "AUTH":
			if arg != "TLS" || !write("234 proceed") {
				return
			}
			control = binding.FTPSImplicitServer(raw)
			reader = bufio.NewReader(control)
		case "USER":
			if arg != "fixture" {
				write("530 denied")
				return
			}
			write("331 password")
		case "PASS":
			if arg != "fixture-password" {
				write("530 denied")
				return
			}
			if binding.AllowData() != nil {
				return
			}
			write("230 accepted")
		case "PBSZ", "PROT", "TYPE":
			write("200 accepted")
		case "SIZE":
			f.mu.Lock()
			b, ok := f.files[arg]
			f.mu.Unlock()
			if !ok {
				write("550 unavailable")
			} else {
				size := int64(len(b))
				if f.reportedSize != nil {
					size = *f.reportedSize
				}
				write(fmt.Sprintf("213 %d", size))
			}
		case "EPSV", "PASV":
			if verb == "EPSV" && f.pasv {
				write("502 EPSV unavailable")
				continue
			}
			if passive != nil {
				passive.Close()
			}
			passive, e = net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				return
			}
			f.mu.Lock()
			f.passive = passive
			f.mu.Unlock()
			port := passive.Addr().(*net.TCPAddr).Port
			if verb == "EPSV" {
				write(fmt.Sprintf("229 Entering (|||%d|)", port))
			} else {
				write(fmt.Sprintf("227 Entering (203,0,113,99,%d,%d)", port/256, port%256))
			}
		case "REST":
			rest, _ = strconv.ParseInt(arg, 10, 64)
			write("350 restart")
		case "STOR", "RETR":
			if passive == nil {
				write("425 unavailable")
				continue
			}
			data, e := passive.Accept()
			passive.Close()
			passive = nil
			if e != nil {
				return
			}
			data.SetDeadline(time.Now().Add(5 * time.Second))
			f.mu.Lock()
			f.data = data
			f.mu.Unlock()
			if !write("150 transfer") {
				data.Close()
				return
			}
			active := binding
			if f.fresh {
				active, e = f.identity.BindFTPSControl(data.LocalAddr())
				if e != nil {
					data.Close()
					return
				}
				defer active.Close()
			}
			secured := active.FTPSImplicitServer(data)
			if verb == "STOR" {
				b, e := io.ReadAll(io.LimitReader(secured, 2<<20))
				if e == nil {
					f.mu.Lock()
					old := f.files[arg]
					if rest <= int64(len(old)) {
						f.files[arg] = append(append([]byte{}, old[:rest]...), b...)
					}
					f.mu.Unlock()
				}
			} else {
				f.mu.Lock()
				b := append([]byte{}, f.files[arg]...)
				f.mu.Unlock()
				_, e = secured.Write(b)
				if f.afterRetrieve != nil {
					f.afterRetrieve()
				}
			}
			if secure.FTPSDataResumed(secured) {
				f.mu.Lock()
				f.resumed++
				f.mu.Unlock()
			}
			if f.unclean {
				data.Close()
			} else {
				secured.Close()
			}
			rest = 0
			if f.drop {
				return
			}
			if !write("226 completed") {
				return
			}
		case "RNFR":
			from = arg
			write("350 rename")
		case "RNTO":
			f.mu.Lock()
			f.files[arg] = f.files[from]
			delete(f.files, from)
			f.mu.Unlock()
			write("250 renamed")
		default:
			write("502 unsupported")
		}
	}
}

func TestClientRefusesTCPClosedDataWithoutTLSShutdown(t *testing.T) {
	for _, operation := range []string{"store", "retrieve"} {
		t.Run(operation, func(t *testing.T) {
			f := newFixture(t, false)
			f.unclean = true
			payload := []byte("exact bytes but no TLS close notification")
			f.files["/stage"] = payload
			f.start()
			c, err := New(context.Background(), f.d, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if operation == "store" {
				_, err = c.StoreStage("/stage", bytes.NewReader(payload), int64(len(payload)), 0, secure.Digest(payload))
			} else {
				err = c.RetrieveToStage("/stage", io.Discard, int64(len(payload)), secure.Digest(payload))
			}
			if err == nil {
				t.Fatal("bare TCP EOF accepted as verified TLS shutdown")
			}
		})
	}
}

func TestClientTransferModesAndExactReadback(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "implicit"}[implicit], func(t *testing.T) {
			f := newFixture(t, implicit)
			f.start()
			c, err := New(context.Background(), f.d, func() error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			payload := bytes.Repeat([]byte("opaque\r\n\x00\xff"), 10000)
			sha := secure.Digest(payload)
			r, err := c.StoreStage("/stage.bin", bytes.NewReader(payload), int64(len(payload)), 0, sha)
			if err != nil || r.BytesSent != int64(len(payload)) || !r.CompletionReplyObserved {
				t.Fatal("store", r, err)
			}
			n, err := c.Size("/stage.bin")
			if err != nil || n != int64(len(payload)) {
				t.Fatal("size", n, err)
			}
			var out bytes.Buffer
			if err = c.RetrieveToStage("/stage.bin", &out, n, sha); err != nil || !bytes.Equal(payload, out.Bytes()) {
				t.Fatal("readback", err)
			}
			if err = c.Rename("/stage.bin", "/final.bin"); err != nil {
				t.Fatal(err)
			}
			if err = c.RetrieveToStage("/final.bin", io.Discard, n, sha); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.resumed != 3 {
				t.Fatal("data did not resume its own control", f.resumed)
			}
		})
	}
}

func TestClientPASVIgnoresAdvertisedForeignAddressAndResumes(t *testing.T) {
	f := newFixture(t, false)
	f.pasv = true
	payload := bytes.Repeat([]byte("resume"), 20000)
	f.files["/stage.bin"] = append([]byte{}, payload[:65536]...)
	f.start()
	c, err := New(context.Background(), f.d, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := c.StoreStage("/stage.bin", bytes.NewReader(payload), int64(len(payload)), 65536, secure.Digest(payload))
	if err != nil || r.BytesSent != int64(len(payload))-65536 {
		t.Fatal(r, err)
	}
	if err = c.RetrieveToStage("/stage.bin", io.Discard, int64(len(payload)), secure.Digest(payload)); err != nil {
		t.Fatal(err)
	}
}

func TestClientDoesNotInventLostCompletionOrAutomaticRetry(t *testing.T) {
	f := newFixture(t, false)
	f.drop = true
	f.start()
	c, err := New(context.Background(), f.d, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte("accepted bytes with an unobserved final reply")
	r, err := c.StoreStage("/stage.bin", bytes.NewReader(payload), int64(len(payload)), 0, secure.Digest(payload))
	if !errors.Is(err, ErrCompletionUnknown) || r.CompletionReplyObserved {
		t.Fatal(r, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Count(strings.Join(f.verbs, " "), "STOR") != 1 || !bytes.Equal(f.files["/stage.bin"], payload) {
		t.Fatal("unobserved result was retried or invented")
	}
}

func TestClientRequiresResumedDataAndTrustedControlBeforeCredentials(t *testing.T) {
	for _, mode := range []string{"wrong-name", "changed-trust", "changed-secret", "unsafe-secret", "fresh-data"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, false)
			d := f.d
			switch mode {
			case "wrong-name":
				d.ServerName = "wrong.invalid"
			case "changed-trust":
				d.CASHA256 = strings.Repeat("0", 64)
			case "changed-secret":
				d.PasswordSHA256 = strings.Repeat("0", 64)
			case "unsafe-secret":
				os.Chmod(d.PasswordFile, 0644)
			case "fresh-data":
				f.fresh = true
			}
			f.start()
			c, err := New(context.Background(), d, func() error { return nil })
			if mode == "fresh-data" {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_, err = c.StoreStage("/stage.bin", bytes.NewReader([]byte("x")), 1, 0, secure.Digest([]byte("x")))
			} else if c != nil {
				c.Close()
			}
			if err == nil {
				t.Fatal("unsafe control/data accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, v := range f.verbs {
				if (mode == "wrong-name" || mode == "changed-trust") && (v == "USER" || v == "PASS") {
					t.Fatal("credentials preceded trust")
				}
				if (mode == "changed-secret" || mode == "unsafe-secret") && v == "PASS" {
					t.Fatal("changed secret sent")
				}
			}
		})
	}
}

func TestClientSourceIntegrityAndLiveGuardCannotPublish(t *testing.T) {
	for _, kind := range []string{"hash", "short", "long", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t, false)
			f.start()
			var revoke atomic.Bool
			c, err := New(context.Background(), f.d, func() error {
				if revoke.Load() {
					return errors.New("private policy details")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			payload := []byte("source")
			size := int64(len(payload))
			hash := secure.Digest(payload)
			switch kind {
			case "hash":
				hash = strings.Repeat("0", 64)
			case "short":
				size++
			case "long":
				size--
			case "revoked":
				revoke.Store(true)
			}
			_, err = c.StoreStage("/stage.bin", bytes.NewReader(payload), size, 0, hash)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid source/authority accepted", err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, v := range f.verbs {
				if v == "RNTO" {
					t.Fatal("failed stage was published")
				}
			}
		})
	}
}

func TestClientReplyAndPassivePortBounds(t *testing.T) {
	for _, text := range []string{"229 (|||21|)", "229 (|||65536|)", "229 (|||+1024|)", "229 garbage", "227 (1,2,3,4,300,1)"} {
		r := reply{code: 229, lines: []string{text}}
		if strings.HasPrefix(text, "227") {
			r.code = 227
		}
		if _, err := passivePort(r); err == nil {
			t.Fatal("invalid passive reply", text)
		}
	}
	f := newFixture(t, false)
	f.banner = "220 " + strings.Repeat("x", 4096)
	f.start()
	if c, err := New(context.Background(), f.d, func() error { return nil }); err == nil {
		c.Close()
		t.Fatal("oversized banner accepted")
	}
}

func TestClientCanceledOrRevokedOperationClosesOwnedSockets(t *testing.T) {
	f := newFixture(t, false)
	f.start()
	ctx, cancel := context.WithCancel(context.Background())
	c, err := New(ctx, f.d, func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation left owned socket/watch alive")
	}
	if _, err = c.Size("/stage.bin"); err == nil {
		t.Fatal("canceled client reused")
	}
}

func TestClientPathGrammarAndMandatoryGuardBeforeNetwork(t *testing.T) {
	for _, path := range []string{"relative", "/../escape", "/a\r\nDELE /other", "/a//b", "/.freightctl/uploads/id", "/CON", "/trailing."} {
		if validPath(path) {
			t.Fatal("unsafe path", path)
		}
	}
	if _, err := New(context.Background(), secure.FTPSDestination{}, nil); !errors.Is(err, ErrInput) {
		t.Fatal("missing live guard accepted", err)
	}
	if _, err := New(context.Background(), secure.FTPSDestination{}, func() error { return errors.New("private details") }); !errors.Is(err, ErrAuthority) {
		t.Fatal("denied guard reached dial", err)
	}
}

func FuzzPassiveReplyNeverEscapesPortBudget(f *testing.F) {
	for _, s := range []string{"229 (|||1024|)", "229 (|||+1024|)", "227 (127,0,0,1,128,1)", "random"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		for _, code := range []int{227, 229} {
			port, err := passivePort(reply{code: code, lines: []string{s}})
			if err == nil && (port < 1024 || port > 65535) {
				t.Fatal("passive port escaped", port)
			}
		}
	})
}

func writeCredentialFixture(t testing.TB, path string, body []byte) {
	t.Helper()
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
}
