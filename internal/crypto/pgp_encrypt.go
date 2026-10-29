package crypto

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"slices"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

const PGPEncryptMDC = "seipd-v1-aes256"
const PGPEncryptAEAD = "seipd-v2-aes256-ocb"

type PGPRecipient struct {
	Fingerprint string   `json:"encryption_fingerprint"`
	Algorithm   string   `json:"encryption_algorithm"`
	Profiles    []string `json:"profiles"`
}
type PGPEncryption struct {
	Backend               string     `json:"backend"`
	PrimaryFingerprint    string     `json:"primary_fingerprint"`
	EncryptionFingerprint string     `json:"encryption_fingerprint"`
	Profile               string     `json:"profile"`
	Cipher                string     `json:"cipher"`
	Compression           string     `json:"compression"`
	EncryptedAt           time.Time  `json:"encrypted_at"`
	ValidUntil            *time.Time `json:"valid_until,omitempty"`
}

// No compression or filename/time hints. The overhead bound includes packet
// framing, a bounded public-key session packet and AEAD chunk authentication.
func PGPCiphertextLimit(size int64) int64 { return size + size/128 + (64 << 10) }

func pgpRecipient(e *openpgp.Entity, now time.Time, until *time.Time) (*PGPRecipient, *time.Time, error) {
	k, ok := e.EncryptionKey(now, pgpConfig(now))
	if !ok {
		return nil, nil, ErrPGPVerification
	}
	algorithm, ok := pgpAlgorithm(k.PublicKey)
	if !ok {
		return nil, nil, ErrPGPInput
	}
	self := k.PrimarySelfSignature
	if self == nil {
		return nil, nil, ErrPGPInput
	}
	profiles := []string{}
	if e.PrimaryKey.Version == 4 && k.PublicKey.Version == 4 && self.SEIPDv1 && slices.Contains(self.PreferredSymmetric, uint8(packet.CipherAES256)) {
		profiles = append(profiles, PGPEncryptMDC)
	}
	if self.SEIPDv2 && slices.Contains(self.PreferredCipherSuites, [2]uint8{uint8(packet.CipherAES256), uint8(packet.AEADModeOCB)}) {
		profiles = append(profiles, PGPEncryptAEAD)
	}
	if len(profiles) == 0 {
		return nil, nil, ErrPGPInput
	}
	until = keyExpiry(until, k.PublicKey, k.SelfSignature)
	return &PGPRecipient{Fingerprint: hex.EncodeToString(k.PublicKey.Fingerprint), Algorithm: algorithm, Profiles: profiles}, until, nil
}

func ParsePGPRecipient(ctx context.Context, wire []byte, expected string, now time.Time) (*PGPPublicKey, error) {
	return parsePGPPublicKey(ctx, wire, expected, now, true)
}

// EncryptPGP writes exactly one authenticated OpenPGP envelope for the enrolled
// encryption subkey and explicit profile. Library packet serializers perform all
// cryptography. No automatic profile fallback, hidden recipient, compression,
// signing key, network lookup or subprocess is used.
func EncryptPGP(ctx context.Context, key PGPPublicKey, profile string, source io.Reader, size int64, digest string, output io.Writer, now time.Time) (*PGPEncryption, error) {
	if key.Purpose != "encrypt" || key.Recipient == nil || !slices.Contains(key.Recipient.Profiles, profile) || (profile != PGPEncryptMDC && profile != PGPEncryptAEAD) || size < 0 || size > 1<<30 || now.IsZero() {
		return nil, ErrPGPInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e, until, err := readPGPEntity(key.Packets, now)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(e.PrimaryKey.Fingerprint) != key.Fingerprint {
		return nil, ErrPGPVerification
	}
	recipient, until, err := pgpRecipient(e, now, until)
	if err != nil || recipient.Fingerprint != key.Recipient.Fingerprint || !slices.Contains(recipient.Profiles, profile) {
		return nil, ErrPGPVerification
	}
	if key.ValidUntil != nil {
		until = earlier(until, *key.ValidUntil)
	}
	if until != nil && !now.Before(*until) {
		return nil, ErrPGPVerification
	}
	k, ok := e.EncryptionKey(now, pgpConfig(now))
	if !ok {
		return nil, ErrPGPVerification
	}
	session := &Secret{Bytes: make([]byte, 32)}
	session.Locked = protect(session.Bytes)
	defer session.Close()
	if _, err = io.ReadFull(rand.Reader, session.Bytes); err != nil {
		return nil, err
	}
	config := pgpConfig(now)
	config.DefaultCipher = packet.CipherAES256
	config.AEADConfig = &packet.AEADConfig{DefaultMode: packet.AEADModeOCB, ChunkSize: 32 << 10}
	aead := profile == PGPEncryptAEAD
	if err = packet.SerializeEncryptedKeyAEAD(output, k.PublicKey, packet.CipherAES256, aead, session.Bytes, config); err != nil {
		return nil, err
	}
	encrypted, err := packet.SerializeSymmetricallyEncrypted(output, packet.CipherAES256, aead, packet.CipherSuite{Cipher: packet.CipherAES256, Mode: packet.AEADModeOCB}, session.Bytes, config)
	if err != nil {
		return nil, err
	}
	literal, err := packet.SerializeLiteral(encrypted, true, "", 0)
	if err != nil {
		_ = encrypted.Close()
		return nil, err
	}
	h := NewDigest()
	input := &pgpSource{ctx: ctx, reader: io.LimitReader(source, size+1), hash: h}
	buffer := make([]byte, 32<<10)
	defer Clear(buffer)
	_, copyErr := io.CopyBuffer(literal, input, buffer)
	closeErr := literal.Close()
	if copyErr != nil {
		return nil, copyErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if input.count != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, ErrPGPVerification
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &PGPEncryption{Backend: PGPBackend, PrimaryFingerprint: key.Fingerprint, EncryptionFingerprint: recipient.Fingerprint, Profile: profile, Cipher: "AES-256", Compression: "none", EncryptedAt: now.UTC(), ValidUntil: until}, nil
}
