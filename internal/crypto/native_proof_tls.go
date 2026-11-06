//go:build integration

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
)

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
