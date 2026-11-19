package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"time"

	"github.com/digitorus/pkcs7"
)

const (
	MaxAS2SignedMessage = MaxAS2SignedEntity + (128 << 10)
	MaxAS2Envelope      = MaxAS2SignedMessage + (16 << 10)
	MaxAS2PrivateKey    = 16 << 10
)

var (
	ErrAS2Envelope  = errors.New("AS2 encrypted message or pinned recipient could not be authenticated")
	oidAuthEnvelope = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
	oidRSAOAEP      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidMGF1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

type authEnvelopeContentInfo struct {
	Type asn1.ObjectIdentifier
	Data asn1.RawValue `asn1:"explicit,tag:0"`
}

type authEnvelope struct {
	Version    int
	Recipients []envelopeRecipient `asn1:"set"`
	Encrypted  envelopeCiphertext
	Tag        []byte
}

type envelopeRecipient struct {
	Version int
	ID      struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	Algorithm pkix.AlgorithmIdentifier
	Key       []byte
}

type envelopeCiphertext struct {
	Type      asn1.ObjectIdentifier
	Algorithm pkix.AlgorithmIdentifier
	Data      asn1.RawValue `asn1:"tag:0"`
}

type as2OAEPParameters struct {
	Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	Mask pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
}

type as2GCMParameters struct {
	Nonce   []byte
	TagSize int
}

// OpenAS2Envelope admits a single-recipient, attribute-free CMS
// AuthEnvelopedData. Go's RSA and AEAD implementations authenticate and decrypt
// it. Callers must still verify the inner sender signature before custody.
func OpenAS2Envelope(wire, certificate, pkcs8 []byte, pin string, now time.Time) (*Secret, error) {
	if len(wire) == 0 || len(wire) > MaxAS2Envelope || len(certificate) == 0 || len(certificate) > MaxAS2Certificate ||
		len(pkcs8) == 0 || len(pkcs8) > MaxAS2PrivateKey || Digest(certificate) != pin {
		return nil, ErrAS2Envelope
	}
	peer, err := x509.ParseCertificate(certificate)
	if err != nil {
		return nil, ErrAS2Envelope
	}
	public := usableAS2Certificate(peer, x509.KeyUsageKeyEncipherment, now)
	if public == nil {
		return nil, ErrAS2Envelope
	}
	recipient, encrypted, ok := readAS2Envelope(wire, peer)
	if !ok || len(recipient.Key) != public.Size() {
		return nil, ErrAS2Envelope
	}
	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	private, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok || len(private.Primes) != 2 || !public.Equal(&private.PublicKey) {
		return nil, ErrAS2Envelope
	}
	contentKey, err := rsa.DecryptOAEP(sha256.New(), nil, private, recipient.Key, nil)
	if err != nil || len(contentKey) != 32 {
		Clear(contentKey)
		return nil, ErrAS2Envelope
	}
	keyBuffer := ProtectBytes(contentKey)
	defer keyBuffer.Close()
	block, err := aes.NewCipher(keyBuffer.Bytes)
	if err != nil {
		return nil, ErrAS2Envelope
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrAS2Envelope
	}
	plain, err := gcm.Open(nil, encrypted.nonce, encrypted.sealed, nil)
	if err != nil {
		return nil, ErrAS2Envelope
	}
	return ProtectBytes(plain), nil
}

type as2SealedCiphertext struct {
	nonce  []byte
	sealed []byte
}

func readAS2Envelope(wire []byte, peer *x509.Certificate) (*envelopeRecipient, as2SealedCiphertext, bool) {
	var empty as2SealedCiphertext
	budget := 4096
	if !boundedCMSDER(wire, 0, &budget) {
		return nil, empty, false
	}
	var outer authEnvelopeContentInfo
	if !exactCMSDER(wire, &outer) || !outer.Type.Equal(oidAuthEnvelope) || !cmsTag(outer.Data, 2, 0) {
		return nil, empty, false
	}
	var envelope authEnvelope
	if !exactCMSDER(outer.Data.Bytes, &envelope) || envelope.Version != 0 || len(envelope.Recipients) != 1 || len(envelope.Tag) != 16 {
		return nil, empty, false
	}
	recipient := &envelope.Recipients[0]
	if recipient.Version != 0 || recipient.ID.Serial == nil || recipient.ID.Serial.Cmp(peer.SerialNumber) != 0 ||
		!bytes.Equal(recipient.ID.Issuer.FullBytes, peer.RawIssuer) || !recipient.Algorithm.Algorithm.Equal(oidRSAOAEP) {
		return nil, empty, false
	}
	var oaep as2OAEPParameters
	var mgfHash pkix.AlgorithmIdentifier
	if !exactCMSDER(recipient.Algorithm.Parameters.FullBytes, &oaep) ||
		!cmsAlgorithm(oaep.Hash, pkcs7.OIDDigestAlgorithmSHA256) || !oaep.Mask.Algorithm.Equal(oidMGF1) ||
		!exactCMSDER(oaep.Mask.Parameters.FullBytes, &mgfHash) || !cmsAlgorithm(mgfHash, pkcs7.OIDDigestAlgorithmSHA256) {
		return nil, empty, false
	}
	content := envelope.Encrypted
	var params as2GCMParameters
	if !content.Type.Equal(pkcs7.OIDData) || !content.Algorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmAES256GCM) ||
		!exactCMSDER(content.Algorithm.Parameters.FullBytes, &params) || len(params.Nonce) != 12 || params.TagSize != len(envelope.Tag) ||
		content.Data.Class != 2 || content.Data.Tag != 0 || content.Data.IsCompound ||
		len(content.Data.Bytes) == 0 || len(content.Data.Bytes) > MaxAS2SignedMessage {
		return nil, empty, false
	}
	sealed := make([]byte, len(content.Data.Bytes)+len(envelope.Tag))
	copy(sealed, content.Data.Bytes)
	copy(sealed[len(content.Data.Bytes):], envelope.Tag)
	return recipient, as2SealedCiphertext{nonce: params.Nonce, sealed: sealed}, true
}

// Re-encoding checks fields that encoding/asn1 might otherwise ignore at the
// end of a sequence. It also keeps BER and extra envelope roles out of this path.
func exactCMSDER[T any](data []byte, result *T) bool {
	rest, err := asn1.Unmarshal(data, result)
	if err != nil || len(rest) != 0 {
		return false
	}
	canonical, err := asn1.Marshal(*result)
	return err == nil && bytes.Equal(data, canonical)
}
