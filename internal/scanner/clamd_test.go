package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

// These peers are adversarial protocol unit fixtures, not ClamAV, vendor
// definitions, a detection corpus or native malware-scanning qualification.
func fixture(t *testing.T) (Definition, time.Time) {
	t.Helper()
	parent, err := os.MkdirTemp("", "freightctl-scan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	dir := filepath.Join(parent, "private")
	if err = protectedfs.EnsureDirectory(dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"db", "tmp"} {
		if err = protectedfs.EnsureDirectory(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	d := Definition{Schema: 1, Kind: Backend, Socket: filepath.Join(dir, "s"), Configuration: filepath.Join(dir, "clamd.conf"), ExpectedVersion: "ClamAV 1.5.4/30001/" + now.Add(-time.Hour).Format("Mon Jan _2 15:04:05 2006"), ValidUntil: now.Add(time.Hour), MaxBytes: 128 << 10, TimeoutSeconds: 2, MaxResultAgeSeconds: 600}
	config := fmt.Sprintf("Foreground yes\nLocalSocket %s\nLocalSocketMode 600\nDatabaseDirectory %s\nTemporaryDirectory %s\nMaxThreads 1\nMaxQueue 2\nStreamMaxLength 131072\nMaxFileSize 131072\nMaxScanSize 262144\nMaxRecursion 4\nMaxFiles 100\nMaxScanTime 1000\nReadTimeout 2\nCommandReadTimeout 2\nSendBufTimeout 1000\nScanArchive yes\nAlertExceedsMax yes\nAlertEncrypted yes\nOfficialDatabaseOnly yes\nBytecode yes\nBytecodeSecurity TrustSigned\nConcurrentDatabaseReload no\nSelfCheck 0\nEnableVersionCommand yes\nEnableReloadCommand no\nEnableShutdownCommand no\nEnableStatsCommand no\n", d.Socket, filepath.Join(dir, "db"), filepath.Join(dir, "tmp"))
	configuration, err := protectedfs.CreateExclusive(d.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = configuration.WriteString(config); err != nil {
		configuration.Close()
		t.Fatal(err)
	}
	if err = configuration.Close(); err != nil {
		t.Fatal(err)
	}
	d.ConfigurationSHA256 = secure.Digest([]byte(config))
	return d, now
}
func peer(t *testing.T, d Definition, mode string, source []byte) {
	t.Helper()
	listener, err := net.Listen("unix", d.Socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	setScannerFixtureSocketPrivacy(t, d.Socket, false)
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("unit fixture did not stop")
		}
	})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		r := bufio.NewReader(c)
		command := func(expected string) bool { v, e := r.ReadString(0); return e == nil && v == expected+"\x00" }
		if !command("zIDSESSION") || !command("zVERSION") {
			return
		}
		v := d.ExpectedVersion
		if mode == "wrong_version" {
			v = strings.Replace(v, "30001", "30002", 1)
		}
		if _, err = io.WriteString(c, "1: "+v+"\x00"); err != nil {
			return
		}
		if !command("zINSTREAM") {
			return
		}
		if mode == "early_ok" {
			_, _ = io.WriteString(c, "2: stream: OK\x00")
			return
		}
		var got bytes.Buffer
		var header [4]byte
		for {
			if _, err = io.ReadFull(r, header[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(header[:])
			if size == 0 {
				break
			}
			if size > 32<<10 {
				return
			}
			if _, err = io.CopyN(&got, r, int64(size)); err != nil {
				return
			}
		}
		if !bytes.Equal(got.Bytes(), source) {
			return
		}
		reply := "2: stream: OK"
		switch mode {
		case "infected":
			reply = "2: stream: Win.Test.EICAR_HDB-1 FOUND"
		case "limit":
			reply = "2: stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND"
		case "encrypted":
			reply = "2: stream: Heuristics.Encrypted.Zip FOUND"
		case "error":
			reply = "2: stream: engine failed ERROR"
		case "missing_id":
			reply = "stream: OK"
		case "oversized":
			reply = strings.Repeat("X", 2050)
		case "control":
			reply = "2: stream: OK\n"
		case "mixed":
			reply = "2: stream: OK\x002: stream: engine failed ERROR"
		}
		if _, err = io.WriteString(c, reply+"\x00"); err != nil {
			return
		}
		if !command("zVERSION") {
			return
		}
		if mode == "version_drift" {
			v = strings.Replace(v, "30001", "30002", 1)
		}
		if _, err = io.WriteString(c, "3: "+v+"\x00"); err != nil {
			return
		}
		if !command("zEND") {
			return
		}
		if mode == "trailing" {
			_, _ = io.WriteString(c, "extra\x00")
		}
	}()
}

type observedScannerSource struct {
	reads int
}

func (s *observedScannerSource) Read(_ []byte) (int, error) {
	s.reads++
	return 0, io.EOF
}

func TestClamdRefusesBroadenedSocketBeforeReadingSource(t *testing.T) {
	d, now := fixture(t)
	body := []byte("synthetic private scanner source")
	peer(t, d, "clean", body)
	private, err := protectedfs.OpenPrivateSocket(d.Socket)
	if err != nil {
		t.Fatal("scanner fixture was not actually private before broadening", err)
	}
	if err = private.Close(); err != nil {
		t.Fatal(err)
	}
	setScannerFixtureSocketPrivacy(t, d.Socket, true)
	if held, err := protectedfs.OpenPrivateSocket(d.Socket); !errors.Is(err, protectedfs.ErrPrivacy) {
		if held != nil {
			held.Close()
		}
		t.Fatal("broad socket fixture did not install actual broad access", err)
	}
	var source observedScannerSource
	checks := 0
	result, err := Scan(t.Context(), d, now, &source, int64(len(body)), secure.Digest(body), func() error { checks++; return nil })
	if !errors.Is(err, ErrUnavailable) || result != nil || source.reads != 0 || checks != 0 {
		t.Fatal("broad socket received source or became a scan verdict", result, err, source.reads, checks)
	}
}

func TestClamdExactStreamAndAdversarialResults(t *testing.T) {
	for _, mode := range []string{"clean", "infected", "limit", "encrypted", "wrong_version", "early_ok", "error", "missing_id", "oversized", "control", "mixed", "version_drift", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			d, now := fixture(t)
			source := bytes.Repeat([]byte("synthetic authorized CSV bytes\r\n"), 2048)
			peer(t, d, mode, source)
			// Keep native transport refusals diagnosable without printing the
			// private fixture path or weakening the scanner's socket checks.
			socket, err := os.Lstat(d.Socket)
			if err != nil {
				t.Fatal("cannot inspect the native scanner fixture socket")
			}
			if socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm()&0077 != 0 {
				t.Logf("native scanner socket metadata: is_socket=%t permission_bits=%#o", socket.Mode()&os.ModeSocket != 0, socket.Mode().Perm())
			}
			var checks atomic.Int32
			result, err := Scan(context.Background(), d, now, bytes.NewReader(source), int64(len(source)), secure.Digest(source), func() error { checks.Add(1); return nil })
			verdicts := map[string]string{"clean": "clean", "infected": "detected", "limit": "blocked", "encrypted": "blocked"}
			if verdict, ok := verdicts[mode]; ok {
				if err != nil || result.Verdict != verdict || result.Bytes != int64(len(source)) || result.SHA256 != secure.Digest(source) || checks.Load() < 3 {
					t.Fatal(result, err)
				}
			} else if err == nil {
				t.Fatal("ambiguous response became a verdict", mode, result)
			}
		})
	}
}
func TestClamdRejectsChangedSourceAndConfiguration(t *testing.T) {
	d, now := fixture(t)
	source := []byte("exact bytes")
	peer(t, d, "clean", source)
	if result, err := Scan(context.Background(), d, now, bytes.NewReader(source), int64(len(source)), secure.Digest([]byte("different")), func() error { return nil }); err == nil || result != nil {
		t.Fatal(result, err)
	}
	config, err := os.ReadFile(d.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(d.Configuration, bytes.Replace(config, []byte("AlertExceedsMax yes"), []byte("AlertExceedsMax no"), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if err = ConfigurationCurrent(context.Background(), d); err == nil {
		t.Fatal("changed config accepted")
	}
	d.ConfigurationSHA256 = secure.Digest(bytes.Replace(config, []byte("AlertExceedsMax yes"), []byte("AlertExceedsMax no"), 1))
	if err = ConfigurationCurrent(context.Background(), d); err == nil {
		t.Fatal("weakened scanner limits accepted")
	}
}
func TestClamdProfileExpiryAndUnsupportedTransport(t *testing.T) {
	d, now := fixture(t)
	if err := Validate(d, now); err != nil {
		t.Fatal(err)
	}
	if err := Validate(d, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired scanner")
	}
	d.Socket = "tcp://127.0.0.1:3310"
	if err := Validate(d, now); err == nil {
		t.Fatal("ambient TCP scanner allowed")
	}
}
func FuzzClamdRecordAndVersion(f *testing.F) {
	f.Add([]byte("2: stream: OK\x00"))
	f.Add([]byte("ClamAV 1.5.4/30001/Thu Oct 29 01:00:00 2026"))
	f.Add([]byte("2: stream: OK\x00bad\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		_, _ = record(bufio.NewReader(bytes.NewReader(data)))
		_, _ = ParseVersion(string(data))
	})
}
