package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditIdentityAndSignaturePolicy(t *testing.T) {
	root := t.TempDir()
	privatePath, publicPath := filepath.Join(root, "audit.key"), filepath.Join(root, "audit.pub")
	if err := GenerateAuditIdentity(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer Clear(original)
	if err = GenerateAuditIdentity(privatePath, publicPath); err == nil {
		t.Fatal("existing identity overwritten")
	}
	after, err := os.ReadFile(privatePath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("identity changed", err)
	}
	Clear(after)
	payload := []byte(`{"format":"freightctl-audit-snapshot-v1","tenant_id":"synthetic"}`)
	envelope, err := SignAuditPayload(privatePath, payload)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		t.Fatal("public PEM missing")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	public := parsed.(ed25519.PublicKey)
	if !ed25519.Verify(public, payload, envelope.Signature) || envelope.KeyFingerprint != Digest(block.Bytes) {
		t.Fatal("signature or fingerprint incorrect")
	}
	changed := append([]byte(nil), payload...)
	changed[len(changed)-1] = ' '
	if ed25519.Verify(public, changed, envelope.Signature) {
		t.Fatal("modified export verified")
	}
	if err = os.Chmod(privatePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = SignAuditPayload(privatePath, payload); err == nil {
		t.Fatal("broad signing-key permissions accepted")
	}
}

func TestAuditSignerRejectsOtherAlgorithmsAndTrailingData(t *testing.T) {
	root := t.TempDir()
	cert, key := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	if err := DevCertificate(cert, key); err != nil {
		t.Fatal(err)
	}
	if _, err := SignAuditPayload(key, []byte("data")); err == nil {
		t.Fatal("TLS EC key accepted for audit signing")
	}
	privatePath, publicPath := filepath.Join(root, "audit.key"), filepath.Join(root, "audit.pub")
	if err := GenerateAuditIdentity(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(privatePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("unexpected trailing data")
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SignAuditPayload(privatePath, []byte("data")); err == nil {
		t.Fatal("ambiguous key file accepted")
	}
}
