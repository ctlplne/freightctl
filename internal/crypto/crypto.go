// Package crypto is the application boundary for cryptographic policy and secrets.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
	"math/big"
	"net"
	"os"
	"runtime"
	"time"
)

func Digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func NewDigest() hash.Hash   { return sha256.New() }
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func Clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Secret owns a bounded buffer. Lock/dump protection is best effort and reported.
type Secret struct {
	Bytes  []byte
	Locked bool
}

func ReadSecret(path string, max int64) (*Secret, error) {
	lst, err := os.Lstat(path)
	if err != nil || !lst.Mode().IsRegular() {
		return nil, errors.New("secret reference must be a regular file, without symlink")
	}
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, errors.New("cannot open secret reference")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !os.SameFile(lst, st) || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() < 1 || st.Size() > max {
		return nil, errors.New("secret must be a bounded regular file with mode 0600 or stricter")
	}
	b := make([]byte, st.Size())
	if _, err = f.ReadAt(b, 0); err != nil {
		Clear(b)
		return nil, errors.New("cannot read secret reference")
	}
	s := &Secret{Bytes: b}
	s.Locked = protect(b)
	return s, nil
}
func (s *Secret) Close() {
	Clear(s.Bytes)
	if s.Locked {
		unprotect(s.Bytes)
	}
	s.Bytes = nil
}
func WriteToken(path string) error {
	b := make([]byte, 32)
	defer Clear(b)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	out := make([]byte, 64)
	defer Clear(out)
	hex.Encode(out, b)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot create token reference")
	}
	defer f.Close()
	if _, err = f.Write(out); err != nil {
		return err
	}
	return f.Sync()
}
func TLSConfig() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }

// Development certificate generation is explicit; production must enroll a trusted identity.
func DevCertificate(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "freightctl loopback development"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(7 * 24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer Clear(k)
	for _, v := range []struct {
		path, kind string
		data       []byte
	}{{keyPath, "PRIVATE KEY", k}, {certPath, "CERTIFICATE", der}} {
		f, e := os.OpenFile(v.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return errors.New("certificate target already exists or cannot be created")
		}
		e = pem.Encode(f, &pem.Block{Type: v.kind, Bytes: v.data})
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
