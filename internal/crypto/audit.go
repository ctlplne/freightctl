package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/ctlplne/freightctl/internal/durablefs"
	"github.com/ctlplne/freightctl/internal/protectedfs"
)

const AuditFormat = "freightctl-audit-snapshot-v1"
const MaxAuditPayload = 16 << 20

// Byte slices encode as base64 in JSON, preserving the exact signed serialization.
type SignedAudit struct {
	Format         string `json:"format"`
	Payload        []byte `json:"payload_base64"`
	Signature      []byte `json:"signature_base64"`
	PublicKeyPEM   string `json:"public_key_pem"`
	KeyFingerprint string `json:"key_sha256_der"`
}

func writeExclusive(path string, data []byte) error {
	f, err := protectedfs.CreateExclusive(path)
	if err != nil {
		return errors.New("identity target already exists or cannot be created")
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return durablefs.SyncDirectory(directory)
}

// GenerateAuditIdentity creates a local signing identity; publication is a separate action.
func GenerateAuditIdentity(privatePath, publicPath string) error {
	if privatePath == publicPath {
		return errors.New("private and public identity paths must differ")
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return errors.New("identity targets must both be new files")
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer Clear(private)
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	defer Clear(key)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
	defer Clear(encoded)
	pub, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	if err = writeExclusive(privatePath, encoded); err != nil {
		return err
	}
	return writeExclusive(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

func SignAuditPayload(keyPath string, payload []byte) (*SignedAudit, error) {
	if len(payload) > MaxAuditPayload {
		return nil, errors.New("audit payload exceeds signing bound")
	}
	secret, err := ReadSecret(keyPath, 4096)
	if err != nil {
		return nil, err
	}
	defer secret.Close()
	block, rest := pem.Decode(secret.Bytes)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("audit signing identity must be one PKCS8 private key")
	}
	defer Clear(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid audit signing identity")
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("audit signing policy requires Ed25519")
	}
	defer Clear(private)
	pub, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return nil, err
	}
	return &SignedAudit{Format: AuditFormat, Payload: payload, Signature: ed25519.Sign(private, payload), PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), KeyFingerprint: Digest(pub)}, nil
}
