//go:build integration

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// NativeProofCertificatePEM serializes a valid public fixture certificate for a
// stock client's CA reference. It never relaxes trust or exposes a private key.
func NativeProofCertificatePEM(der []byte) ([]byte, error) {
	if len(der) < 1 || len(der) > 128<<10 {
		return nil, errors.New("invalid bounded public fixture certificate")
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return nil, errors.New("invalid public fixture certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// NativeProofTLS is available only to explicit integration builds. It loads a
// protected generated identity through the ordinary key loader and pins its
// certificate as the fixture trust root. Callers consume both immutable TLS1.3
// configurations;they must never relax verification or alter the identity.
func NativeProofTLS(certFile, keyFile string) (client, server *TLSConfiguration, err error) {
	identity, err := LoadFTPSIdentity(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := ReadSecret(certFile, 128<<10)
	if err != nil {
		return nil, nil, errors.New("native TLS proof requires a protected certificate reference")
	}
	defer certificate.Close()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate.Bytes) {
		return nil, nil, errors.New("native TLS proof certificate cannot establish trust")
	}
	client = TLSConfig()
	client.RootCAs = pool
	server = TLSConfig()
	server.Certificates = []tls.Certificate{identity.certificate}
	return client, server, nil
}
