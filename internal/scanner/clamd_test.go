package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
)

// These peers are adversarial protocol unit fixtures, not ClamAV, vendor
// definitions, a detection corpus or native malware-scanning qualification.
func fixture(t *testing.T) (Definition, time.Time) {
	t.Helper()
	dir, err := os.MkdirTemp("", "freightctl-scan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	for _, name := range []string{"db", "tmp"} {
		if err = os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	d := Definition{Schema: 1, Kind: Backend, Socket: filepath.Join(dir, "s"), Configuration: filepath.Join(dir, "clamd.conf"), ExpectedVersion: "ClamAV 1.5.4/30001/" + now.Add(-time.Hour).Format("Mon Jan _2 15:04:05 2006"), ValidUntil: now.Add(time.Hour), MaxBytes: 128 << 10, TimeoutSeconds: 2, MaxResultAgeSeconds: 600}
	config := fmt.Sprintf("Foreground yes\nLocalSocket %s\nLocalSocketMode 600\nDatabaseDirectory %s\nTemporaryDirectory %s\nMaxThreads 1\nMaxQueue 2\nStreamMaxLength 131072\nMaxFileSize 131072\nMaxScanSize 262144\nMaxRecursion 4\nMaxFiles 100\nMaxScanTime 1000\nReadTimeout 2\nCommandReadTimeout 2\nSendBufTimeout 1000\nScanArchive yes\nAlertExceedsMax yes\nAlertEncrypted yes\nOfficialDatabaseOnly yes\nBytecode yes\nBytecodeSecurity TrustSigned\nConcurrentDatabaseReload no\nSelfCheck 0\nEnableVersionCommand yes\nEnableReloadCommand no\nEnableShutdownCommand no\nEnableStatsCommand no\n", d.Socket, filepath.Join(dir, "db"), filepath.Join(dir, "tmp"))
	if err = os.WriteFile(d.Configuration, []byte(config), 0600); err != nil {
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
	if err = os.Chmod(d.Socket, 0600); err != nil {
		t.Fatal(err)
	}
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
func TestClamdExactStreamAndAdversarialResults(t *testing.T) {
	for _, mode := range []string{"clean", "infected", "limit", "encrypted", "wrong_version", "early_ok", "error", "missing_id", "oversized", "control", "mixed", "version_drift", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			d, now := fixture(t)
			source := bytes.Repeat([]byte("synthetic authorized CSV bytes\r\n"), 2048)
			peer(t, d, mode, source)
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
