//go:build integration

package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGnuPGIndependentlyDecryptsExactRecipientEnvelope(t *testing.T) {
	dir := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	if dir == "" {
		t.Fatal("independent GnuPG recipient fixture required")
	}
	var fixture struct {
		Fingerprints map[string]string `json:"fingerprints"`
		Image        string            `json:"peer_image"`
	}
	load := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if err := json.Unmarshal(load("manifest.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"recipient", "recipient-rsa"} {
		now := time.Now().UTC()
		key, err := ParsePGPRecipient(context.Background(), load(name+"-public.gpg"), fixture.Fingerprints[name], now)
		if err != nil {
			t.Fatal(name, err)
		}
		work := t.TempDir()
		source := load("source.csv")
		var encrypted bytes.Buffer
		proof, err := EncryptPGP(context.Background(), *key, PGPEncryptMDC, bytes.NewReader(source), int64(len(source)), Digest(source), &encrypted, now)
		if err != nil || proof.PrimaryFingerprint != fixture.Fingerprints[name] {
			t.Fatal(proof, err)
		}
		if err = os.WriteFile(filepath.Join(work, "cipher.pgp"), encrypted.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		command := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--cpus=1", "--pids-limit=32", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "-v", dir+":/fixture:ro", "-v", work+":/result", fixture.Image, "/bin/sh", "-ec", "mkdir -m 700 /tmp/recipient; : > /tmp/recipient/common.conf; gpg --homedir /tmp/recipient --batch --import /fixture/"+name+"-private.gpg; gpg --homedir /tmp/recipient --batch --status-fd 2 --output /result/plain.csv --decrypt /result/cipher.pgp")
		output, err := command.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("independent GnuPG recipient: %v: %s", err, output)
		}
		plain, err := os.ReadFile(filepath.Join(work, "plain.csv"))
		if err != nil || !bytes.Equal(plain, source) || !strings.Contains(string(output), "DECRYPTION_OKAY") || !strings.Contains(string(output), "GOODMDC") || !strings.Contains(string(output), "DECRYPTION_INFO 2 9 0") {
			t.Fatal("stock recipient did not confirm AES256/exact authenticated bytes", err, string(output))
		}
	}
}
