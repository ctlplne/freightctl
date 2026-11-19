package crypto

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"

	"github.com/digitorus/pkcs7"
)

const (
	MaxAS2SignedReport = 64 << 10
	MaxAS2SignedEntity = 8 << 20
	MaxAS2CMSSignature = 32 << 10
	MaxAS2Certificate  = 16 << 10
)

var ErrAS2Signature = errors.New("AS2 CMS signature or pinned peer certificate verification failed")

func SignAS2DetachedCMS(entity, certificate, pkcs8 []byte, pin string, now time.Time) ([]byte, error) {
	if len(entity) == 0 || len(entity) > MaxAS2SignedEntity {
		return nil, ErrAS2Signature
	}
	signer, public := parseAS2Leaf(certificate, pin, x509.KeyUsageDigitalSignature, now)
	if public == nil {
		return nil, ErrAS2Signature
	}
	private := parseAS2PrivateKey(pkcs8, public)
	if private == nil {
		return nil, ErrAS2Signature
	}
	signed, err := pkcs7.NewSignedData(entity)
	if err != nil {
		return nil, ErrAS2Signature
	}
	signed.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	signed.SetEncryptionAlgorithm(pkcs7.OIDEncryptionAlgorithmRSASHA256)
	if err = signed.AddSigner(signer, private, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, ErrAS2Signature
	}
	signed.Detach()
	signature, err := signed.Finish()
	if err != nil || len(signature) == 0 || len(signature) > MaxAS2CMSSignature {
		return nil, ErrAS2Signature
	}
	return signature, nil
}

// VerifyAS2DetachedCMS checks one SHA-256/RSA signature from the exact
// configured peer certificate. The library verifies the signature over the
// original bytes. The AS2 profile checks the certificate at observation time.
func VerifyAS2DetachedCMS(report, signature, certificate []byte, pin string, now time.Time) error {
	if len(report) == 0 || len(report) > MaxAS2SignedEntity ||
		len(signature) == 0 || len(signature) > MaxAS2CMSSignature ||
		len(certificate) == 0 || len(certificate) > MaxAS2Certificate ||
		Digest(certificate) != pin || now.IsZero() {
		return ErrAS2Signature
	}
	rawAttributes, ok := as2DetachedAttributes(signature)
	if !ok {
		return ErrAS2Signature
	}
	signed, err := pkcs7.Parse(signature)
	if err != nil || len(signed.Signers) != 1 || len(signed.Certificates) != 1 || len(signed.CRLs) != 0 {
		return ErrAS2Signature
	}
	peer := signed.GetOnlySigner()
	if usableAS2Certificate(peer, x509.KeyUsageDigitalSignature, now) == nil || !bytes.Equal(peer.Raw, certificate) {
		return ErrAS2Signature
	}
	signer := signed.Signers[0]
	signatureAlgorithm := signer.DigestEncryptionAlgorithm.Algorithm
	if signer.Version != 1 || !cmsAlgorithm(signer.DigestAlgorithm, pkcs7.OIDDigestAlgorithmSHA256) ||
		!(signatureAlgorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) || signatureAlgorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSASHA256)) ||
		!cmsAlgorithm(signer.DigestEncryptionAlgorithm, signatureAlgorithm) ||
		len(signer.AuthenticatedAttributes) < 2 || len(signer.AuthenticatedAttributes) > 16 ||
		len(signer.UnauthenticatedAttributes) != 0 {
		return ErrAS2Signature
	}
	seen := make(map[string]bool, len(signer.AuthenticatedAttributes))
	for _, attribute := range signer.AuthenticatedAttributes {
		name := attribute.Type.String()
		if seen[name] || !cmsOneValue(attribute.Value.Bytes) {
			return ErrAS2Signature
		}
		seen[name] = true
	}
	// CMS signs the DER SET encoding of these attributes. Compare the
	// library's encoding to the input with only the implicit tag replaced.
	canonical, err := asn1.MarshalWithParams(signer.AuthenticatedAttributes, "set")
	if err != nil || len(canonical) != len(rawAttributes) || !bytes.Equal(canonical[1:], rawAttributes[1:]) {
		return ErrAS2Signature
	}
	var contentType asn1.ObjectIdentifier
	var digest []byte
	if signed.UnmarshalSignedAttribute(pkcs7.OIDAttributeContentType, &contentType) != nil ||
		!contentType.Equal(pkcs7.OIDData) ||
		signed.UnmarshalSignedAttribute(pkcs7.OIDAttributeMessageDigest, &digest) != nil || len(digest) != 32 {
		return ErrAS2Signature
	}
	signed.Content = report
	if signed.VerifyWithChainAtTime(nil, now) != nil {
		return ErrAS2Signature
	}
	return nil
}

func usableAS2Certificate(peer *x509.Certificate, keyUsage x509.KeyUsage, now time.Time) *rsa.PublicKey {
	if peer == nil || peer.IsCA || peer.KeyUsage&keyUsage == 0 || len(peer.UnhandledCriticalExtensions) != 0 ||
		now.IsZero() || now.Before(peer.NotBefore) || !now.Before(peer.NotAfter) {
		return nil
	}
	key, ok := peer.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() < 3072 || key.N.BitLen() > 8192 || key.E != 65537 {
		return nil
	}
	if len(peer.ExtKeyUsage)+len(peer.UnknownExtKeyUsage) == 0 {
		return key
	}
	for _, usage := range peer.ExtKeyUsage {
		if usage == x509.ExtKeyUsageEmailProtection {
			return key
		}
	}
	return nil
}

// Check the envelope before passing it to the library's BER decoder. The
// receipt profile admits finite DER only, with no embedded content or CRLs.
func as2DetachedAttributes(signature []byte) ([]byte, bool) {
	remaining := 4096
	if !boundedCMSDER(signature, 0, &remaining) {
		return nil, false
	}
	var root asn1.RawValue
	rest, err := asn1.Unmarshal(signature, &root)
	if err != nil || len(rest) != 0 || !cmsTag(root, 0, asn1.TagSequence) {
		return nil, false
	}
	var contentType asn1.ObjectIdentifier
	fields, err := asn1.Unmarshal(root.Bytes, &contentType)
	if err != nil || !contentType.Equal(pkcs7.OIDSignedData) {
		return nil, false
	}
	var wrapper, sequence asn1.RawValue
	rest, err = asn1.Unmarshal(fields, &wrapper)
	if err != nil || len(rest) != 0 || !cmsTag(wrapper, 2, 0) {
		return nil, false
	}
	rest, err = asn1.Unmarshal(wrapper.Bytes, &sequence)
	if err != nil || len(rest) != 0 || !cmsTag(sequence, 0, asn1.TagSequence) {
		return nil, false
	}
	var version int
	fields, err = asn1.Unmarshal(sequence.Bytes, &version)
	if err != nil || version != 1 {
		return nil, false
	}
	var digestAlgorithms, content, certificates, signers asn1.RawValue
	for _, field := range []*asn1.RawValue{&digestAlgorithms, &content, &certificates, &signers} {
		fields, err = asn1.Unmarshal(fields, field)
		if err != nil {
			return nil, false
		}
	}
	if len(fields) != 0 || !cmsTag(digestAlgorithms, 0, asn1.TagSet) ||
		!cmsTag(content, 0, asn1.TagSequence) || !cmsTag(certificates, 2, 0) ||
		!cmsTag(signers, 0, asn1.TagSet) || !cmsOneValue(certificates.Bytes) {
		return nil, false
	}
	var algorithm pkix.AlgorithmIdentifier
	rest, err = asn1.Unmarshal(digestAlgorithms.Bytes, &algorithm)
	if err != nil || len(rest) != 0 || !cmsAlgorithm(algorithm, pkcs7.OIDDigestAlgorithmSHA256) {
		return nil, false
	}
	rest, err = asn1.Unmarshal(content.Bytes, &contentType)
	if err != nil || len(rest) != 0 || !contentType.Equal(pkcs7.OIDData) {
		return nil, false
	}
	rest, err = asn1.Unmarshal(signers.Bytes, &sequence)
	if err != nil || len(rest) != 0 || !cmsTag(sequence, 0, asn1.TagSequence) {
		return nil, false
	}
	var signerFields [6]asn1.RawValue
	fields = sequence.Bytes
	for i := range signerFields {
		fields, err = asn1.Unmarshal(fields, &signerFields[i])
		if err != nil {
			return nil, false
		}
	}
	attributes := signerFields[3]
	return attributes.FullBytes, len(fields) == 0 && cmsTag(attributes, 2, 0)
}

func cmsAlgorithm(algorithm pkix.AlgorithmIdentifier, oid asn1.ObjectIdentifier) bool {
	parameters := algorithm.Parameters.FullBytes
	return algorithm.Algorithm.Equal(oid) && (len(parameters) == 0 || bytes.Equal(parameters, []byte{asn1.TagNull, 0}))
}

func cmsTag(value asn1.RawValue, class, tag int) bool {
	return value.Class == class && value.Tag == tag && value.IsCompound
}

func cmsOneValue(wire []byte) bool {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(wire, &value)
	return err == nil && len(rest) == 0
}

func boundedCMSDER(wire []byte, depth int, remaining *int) bool {
	if depth > 24 {
		return false
	}
	for len(wire) != 0 {
		if *remaining == 0 {
			return false
		}
		(*remaining)--
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(wire, &value)
		if err != nil || len(rest) >= len(wire) {
			return false
		}
		if value.Class == 0 && (value.Tag == 0 || value.IsCompound != (value.Tag == asn1.TagSequence || value.Tag == asn1.TagSet)) {
			return false
		}
		if value.IsCompound && !boundedCMSDER(value.Bytes, depth+1, remaining) {
			return false
		}
		wire = rest
	}
	return true
}
