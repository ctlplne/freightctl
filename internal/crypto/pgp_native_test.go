//go:build integration

package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGnuPGDetachedInteroperabilityAndRefusal(t *testing.T) {
	dir := os.Getenv("FREIGHTCTL_TEST_PGP_DIR")
	if dir == "" {
		t.Fatal("independent GnuPG fixture reference required")
	}
	var fixture struct {
		Fingerprints map[string]string `json:"fingerprints"`
	}
	load := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := json.Unmarshal(load("manifest.json"), &fixture); err != nil {
		t.Fatal(err)
	}
	source := load("source.csv")
	now := time.Now().UTC()
	for _, name := range []string{"good", "rsa"} {
		key, err := ParsePGPPublicKey(context.Background(), load(name+"-public.gpg"), fixture.Fingerprints[name], now)
		if err != nil {
			t.Fatal(name, err)
		}
		proof, err := VerifyPGPDetached(context.Background(), *key, load(name+".sig"), bytes.NewReader(source), int64(len(source)), Digest(source), now, 0)
		if err != nil || proof.PrimaryFingerprint != fixture.Fingerprints[name] {
			t.Fatal(name, proof, err)
		}
		if name == "good" && proof.SignerFingerprint != fixture.Fingerprints["subkey"] {
			t.Fatal("signing subkey was not bound to approved primary", proof)
		}
		changed := bytes.Replace(source, []byte("100.01"), []byte("100.02"), 1)
		if _, err = VerifyPGPDetached(context.Background(), *key, load(name+".sig"), bytes.NewReader(changed), int64(len(changed)), Digest(changed), now, 0); err == nil {
			t.Fatal("changed independently signed data accepted")
		}
	}
	key, err := ParsePGPPublicKey(context.Background(), load("good-public.asc"), fixture.Fingerprints["good"], now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyPGPDetached(context.Background(), *key, load("good.sig.asc"), bytes.NewReader(source), int64(len(source)), Digest(source), now, 0); err != nil {
		t.Fatal("armored independent signature", err)
	}
	for _, sig := range []string{"other.sig", "aged.sig"} {
		if _, err = VerifyPGPDetached(context.Background(), *key, load(sig), bytes.NewReader(source), int64(len(source)), Digest(source), now, 60); err == nil {
			t.Fatal("wrong signer or stale signature accepted", sig)
		}
	}
	for _, input := range []struct{ File, Pin string }{{"expired-public.gpg", "expired"}, {"revoked-public.gpg", "good"}, {"private-rejection.gpg", "good"}, {"good-public.gpg", "other"}} {
		if _, err = ParsePGPPublicKey(context.Background(), load(input.File), fixture.Fingerprints[input.Pin], now); err == nil {
			t.Fatal("untrusted key accepted", input.File)
		}
	}
	if InspectPGPSignature(load("weak.sig")) == nil {
		t.Fatal("SHA1 signature admitted")
	}
	if InspectPGPSignature(append(load("good.sig"), load("other.sig")...)) == nil {
		t.Fatal("mixed multiple signatures admitted")
	}
	if !strings.Contains(string(load("good-verification.txt")), "VALIDSIG") {
		t.Fatal("independent peer did not verify its native artifact")
	}
}
