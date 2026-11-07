//go:build ftpspeer

package ftpsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

// This profile is intentionally separate from unit stand-ins. Its supervisor
// launches stock vsftpd/OpenSSL/PAM on actual native Linux GitHub runners.
func TestNativeStockReceiver(t *testing.T) {
	ref := os.Getenv("FREIGHTCTL_FTPS_RECEIVER_FILE")
	st, err := os.Lstat(ref)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 16384 {
		t.Fatal("exact protected stock receiver reference required")
	}
	f, err := os.Open(ref)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var cfg struct {
		Explicit secure.FTPSDestination `json:"explicit"`
		Implicit secure.FTPSDestination `json:"implicit"`
		Metadata bool                   `json:"collection_metadata"`
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if err = d.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if err = d.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("trailing stock receiver configuration")
	}
	for _, entry := range []struct {
		mode        string
		destination secure.FTPSDestination
	}{{"explicit", cfg.Explicit}, {"implicit", cfg.Implicit}} {
		t.Run(entry.mode, func(t *testing.T) {
			if entry.destination.Mode != entry.mode {
				t.Fatal("mode differs")
			}
			client, err := New(context.Background(), entry.destination, func() error { return nil })
			if err != nil {
				t.Fatal("stock receiver connection", err)
			}
			defer client.Close()
			payload := []byte("account,amount,day\n" + stringsRepeatRow())
			hash := secure.Digest(payload)
			base := "/inbox/" + entry.mode
			result, err := client.StoreStage(base+"-stage.csv", bytes.NewReader(payload), int64(len(payload)), 0, hash)
			if err != nil || !result.CompletionReplyObserved || result.BytesSent != int64(len(payload)) {
				t.Fatal("stock store", result, err)
			}
			size, err := client.Size(base + "-stage.csv")
			if err != nil || size != int64(len(payload)) {
				t.Fatal("stock size", size, err)
			}
			var readback bytes.Buffer
			if err = client.RetrieveToStage(base+"-stage.csv", &readback, size, hash); err != nil || !bytes.Equal(readback.Bytes(), payload) {
				t.Fatal("stock independent readback", err)
			}
			if err = client.Rename(base+"-stage.csv", base+"-final.csv"); err != nil {
				t.Fatal("stock rename", err)
			}
			if err = client.RetrieveToStage(base+"-final.csv", io.Discard, size, hash); err != nil {
				t.Fatal("stock renamed readback", err)
			}
			prefix := payload[:65536]
			if _, err = client.StoreStage(base+"-resume.csv", bytes.NewReader(prefix), 65536, 0, secure.Digest(prefix)); err != nil {
				t.Fatal("stock prefix", err)
			}
			result, err = client.StoreStage(base+"-resume.csv", bytes.NewReader(payload), size, 65536, hash)
			if err != nil || result.BytesSent != size-65536 {
				t.Fatal("stock resume", result, err)
			}
			if err = client.RetrieveToStage(base+"-resume.csv", io.Discard, size, hash); err != nil {
				t.Fatal("stock resumed integrity", err)
			}
			if _, err = client.StoreStage(base+"-empty", bytes.NewReader(nil), 0, 0, secure.Digest(nil)); err != nil {
				t.Fatal("stock zero-byte upload", err)
			}
			if err = client.RetrieveToStage(base+"-empty", io.Discard, 0, secure.Digest(nil)); err != nil {
				t.Fatal("stock zero-byte readback", err)
			}
			if cfg.Metadata {
				qualifyStockMetadata(t, client, entry.mode, payload)
			}
			wrong := entry.destination
			wrong.ServerName = "unapproved.invalid"
			if c, e := New(context.Background(), wrong, func() error { return nil }); e == nil {
				c.Close()
				t.Fatal("stock wrong identity accepted")
			}
			bad := filepath.Join(t.TempDir(), "wrong-password")
			writeCredentialFixture(t, bad, []byte("not-the-enrolled-password"))
			wrong = entry.destination
			wrong.PasswordFile = bad
			wrong.PasswordSHA256 = secure.Digest([]byte("not-the-enrolled-password"))
			if c, e := New(context.Background(), wrong, func() error { return nil }); e == nil {
				c.Close()
				t.Fatal("stock invalid password accepted")
			}
		})
	}
}

func stringsRepeatRow() string { return string(bytes.Repeat([]byte("0001,1.01,2026-10-28\n"), 10000)) }

func qualifyStockMetadata(t *testing.T, client *Client, mode string, payload []byte) {
	t.Helper()
	base := "/inbox/" + mode
	// The independent host producer publishes these exact read-only source
	// names. This client must never upload or rename the metadata fixtures.
	expected := []byte(fmt.Sprintf("{\"schema_version\":1,\"batch_id\":\"11111111-2222-4333-8444-555555555555\",\"files\":[{\"name\":\"%s-final.csv\",\"size_bytes\":%d,\"sha256\":\"%s\"}]}\n", mode, len(payload), secure.Digest(payload)))
	ready, err := client.ReadBounded(base+"-ready.json", MaxMetadata)
	if err != nil || !bytes.Equal(ready, expected) {
		t.Fatal("stock metadata exact published bytes", err)
	}
	maximum, err := client.ReadBounded(base+"-max.metadata", MaxMetadata)
	if err != nil || !bytes.Equal(maximum, bytes.Repeat([]byte("M"), int(MaxMetadata))) {
		t.Fatal("stock metadata exact maximum", err)
	}
	empty, err := client.ReadBounded(base+"-empty", MaxMetadata)
	if err != nil || len(empty) != 0 {
		t.Fatal("stock metadata exact empty object", err)
	}
	if partial, err := client.ReadBounded(base+"-oversize.metadata", MaxMetadata); !errors.Is(err, ErrInput) || partial != nil {
		t.Fatal("stock metadata oversize returned bytes or wrong refusal", err)
	}
	again, err := client.ReadBounded(base+"-ready.json", MaxMetadata)
	if err != nil || !bytes.Equal(again, expected) {
		t.Fatal("stock metadata bounded refusal damaged the original control session", err)
	}
	proof := struct {
		Kind        string `json:"kind"`
		Mode        string `json:"mode"`
		ReadySize   int    `json:"ready_size"`
		ReadyHash   string `json:"ready_sha256"`
		MaximumSize int    `json:"maximum_size"`
		MaximumHash string `json:"maximum_sha256"`
		EmptySize   int    `json:"empty_size"`
		EmptyHash   string `json:"empty_sha256"`
		Oversize    bool   `json:"oversize_refused"`
		Usable      bool   `json:"session_usable_after_refusal"`
	}{"freightctl-stock-ftps-metadata-v1", mode, len(ready), secure.Digest(ready), len(maximum), secure.Digest(maximum), len(empty), secure.Digest(empty), true, true}
	if err := json.NewEncoder(os.Stdout).Encode(proof); err != nil {
		t.Fatal(err)
	}
}
