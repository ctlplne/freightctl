package crypto

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

const PGPBackend = "ProtonMail/go-crypto/v1.5.2/openpgp/v2"
const MaxPGPWire = 32 << 10
const MaxPGPBinary = 16 << 10

var ErrPGPInput = errors.New("unsupported or malformed bounded OpenPGP public key or detached binary signature")
var ErrPGPVerification = errors.New("OpenPGP signature, signer, time or exact source verification failed")

type PGPPublicKey struct {
	Schema      int           `json:"schema_version"`
	Packets     []byte        `json:"public_packets"`
	Fingerprint string        `json:"fingerprint"`
	Algorithm   string        `json:"algorithm"`
	Version     int           `json:"key_version"`
	Created     time.Time     `json:"created_at"`
	ValidUntil  *time.Time    `json:"valid_until,omitempty"`
	Purpose     string        `json:"purpose,omitempty"`
	Recipient   *PGPRecipient `json:"recipient,omitempty"`
}
type PGPVerification struct {
	Backend            string     `json:"backend"`
	PrimaryFingerprint string     `json:"primary_fingerprint"`
	SignerFingerprint  string     `json:"signer_fingerprint"`
	SignatureSHA256    string     `json:"signature_sha256"`
	Hash               string     `json:"hash_algorithm"`
	SignatureVersion   int        `json:"signature_version"`
	Created            time.Time  `json:"created_at"`
	VerifiedAt         time.Time  `json:"verified_at"`
	ValidUntil         *time.Time `json:"valid_until,omitempty"`
}

func pgpConfig(now time.Time) *packet.Config {
	return &packet.Config{Time: func() time.Time { return now }, MinRSABits: 3072, RejectHashAlgorithms: map[crypto.Hash]bool{crypto.MD5: true, crypto.SHA1: true, crypto.RIPEMD160: true, crypto.SHA224: true}, RejectMessageHashAlgorithms: map[crypto.Hash]bool{crypto.MD5: true, crypto.SHA1: true, crypto.RIPEMD160: true, crypto.SHA224: true}}
}
func pgpBinary(wire []byte, kind string) ([]byte, error) {
	if len(wire) < 2 || len(wire) > MaxPGPWire {
		return nil, ErrPGPInput
	}
	trimmed := bytes.TrimSpace(wire)
	if bytes.HasPrefix(trimmed, []byte("-----")) {
		begin, end := []byte("-----BEGIN "+kind+"-----"), []byte("-----END "+kind+"-----")
		if !bytes.HasPrefix(trimmed, begin) || !bytes.HasSuffix(trimmed, end) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 || bytes.Count(trimmed, []byte("-----END ")) != 1 {
			return nil, ErrPGPInput
		}
		block, err := armor.Decode(bytes.NewReader(trimmed))
		if err != nil || block.Type != kind {
			return nil, ErrPGPInput
		}
		data, err := io.ReadAll(io.LimitReader(block.Body, MaxPGPBinary+1))
		if err != nil || len(data) > MaxPGPBinary {
			return nil, ErrPGPInput
		}
		return data, nil
	}
	if len(wire) > MaxPGPBinary {
		return nil, ErrPGPInput
	}
	return bytes.Clone(wire), nil
}

// This is a framing/admission guard, not a cryptographic implementation. Reject
// secret, compressed, literal, partial-length and unknown packets before the
// library allocates or interprets their bodies. Cryptography stays in the library.
func pgpFraming(data []byte, signature bool) error {
	count, primaries, identities, subkeys := 0, 0, 0, 0
	for offset := 0; offset < len(data); {
		count++
		if count > 64 {
			return ErrPGPInput
		}
		head := data[offset]
		offset++
		if head&128 == 0 {
			return ErrPGPInput
		}
		tag := int(head & 63)
		var length uint64
		take := func(n int) ([]byte, bool) {
			if n > len(data)-offset {
				return nil, false
			}
			b := data[offset : offset+n]
			offset += n
			return b, true
		}
		if head&64 != 0 {
			b, ok := take(1)
			if !ok {
				return ErrPGPInput
			}
			first := b[0]
			switch {
			case first < 192:
				length = uint64(first)
			case first < 224:
				b, ok = take(1)
				if !ok {
					return ErrPGPInput
				}
				length = uint64(first-192)*256 + uint64(b[0]) + 192
			case first == 255:
				b, ok = take(4)
				if !ok {
					return ErrPGPInput
				}
				length = uint64(binary.BigEndian.Uint32(b))
			default:
				return ErrPGPInput
			}
		} else {
			tag = int((head >> 2) & 15)
			size := 1 << uint(head&3)
			if size == 8 {
				return ErrPGPInput
			}
			b, ok := take(size)
			if !ok {
				return ErrPGPInput
			}
			for _, v := range b {
				length = length*256 + uint64(v)
			}
		}
		if length == 0 || length > uint64(len(data)-offset) {
			return ErrPGPInput
		}
		if signature {
			if tag != 2 || count != 1 {
				return ErrPGPInput
			}
		} else {
			switch tag {
			case 6:
				primaries++
				if primaries != 1 || count != 1 {
					return ErrPGPInput
				}
			case 13:
				identities++
				if identities > 8 {
					return ErrPGPInput
				}
			case 14:
				subkeys++
				if subkeys > 8 {
					return ErrPGPInput
				}
			case 2:
			default:
				return ErrPGPInput
			}
		}
		if tag == 2 || tag == 6 || tag == 14 {
			if data[offset] != 4 && data[offset] != 6 {
				return ErrPGPInput
			}
		}
		offset += int(length)
	}
	if count == 0 || (!signature && primaries != 1) {
		return ErrPGPInput
	}
	return nil
}
func pgpAlgorithm(p *packet.PublicKey) (string, bool) {
	switch p.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly, packet.PubKeyAlgoRSAEncryptOnly:
		bits, err := p.BitLength()
		return "rsa", err == nil && bits >= 3072 && bits <= 8192
	case packet.PubKeyAlgoEd25519:
		return "ed25519", true
	case packet.PubKeyAlgoEd448:
		return "ed448", true
	case packet.PubKeyAlgoEdDSA:
		curve, err := p.Curve()
		return "eddsa", err == nil && curve == packet.Curve25519 && p.Version == 4
	case packet.PubKeyAlgoECDSA, packet.PubKeyAlgoECDH:
		curve, err := p.Curve()
		allowed := curve == packet.Curve("P256") || curve == packet.Curve("P384") || curve == packet.Curve("P521") || (p.PubKeyAlgo == packet.PubKeyAlgoECDH && curve == packet.Curve25519)
		return "elliptic", err == nil && allowed
	case packet.PubKeyAlgoX25519:
		return "x25519", true
	case packet.PubKeyAlgoX448:
		return "x448", true
	}
	return "", false
}
func earlier(a *time.Time, b time.Time) *time.Time {
	if a == nil || b.Before(*a) {
		v := b.UTC()
		return &v
	}
	return a
}
func keyExpiry(until *time.Time, pub *packet.PublicKey, sig *packet.Signature) *time.Time {
	if sig == nil {
		return until
	}
	if sig.KeyLifetimeSecs != nil && *sig.KeyLifetimeSecs > 0 {
		until = earlier(until, pub.CreationTime.Add(time.Duration(*sig.KeyLifetimeSecs)*time.Second))
	}
	if sig.SigLifetimeSecs != nil && *sig.SigLifetimeSecs > 0 {
		until = earlier(until, sig.CreationTime.Add(time.Duration(*sig.SigLifetimeSecs)*time.Second))
	}
	return until
}
func readPGPEntity(data []byte, now time.Time) (*openpgp.Entity, *time.Time, error) {
	if now.IsZero() || pgpFraming(data, false) != nil {
		return nil, nil, ErrPGPInput
	}
	entities, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil || len(entities) != 1 {
		return nil, nil, ErrPGPInput
	}
	e := entities[0]
	if e.PrivateKey != nil || len(e.Subkeys) > 8 || len(e.Identities) > 8 {
		return nil, nil, ErrPGPInput
	}
	if _, ok := pgpAlgorithm(e.PrimaryKey); !ok || !e.PrimaryKey.PubKeyAlgo.CanSign() {
		return nil, nil, ErrPGPInput
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil {
			return nil, nil, ErrPGPInput
		}
		if _, ok := pgpAlgorithm(sub.PublicKey); !ok {
			return nil, nil, ErrPGPInput
		}
	}
	self, err := e.VerifyPrimaryKey(now, pgpConfig(now))
	if err != nil {
		return nil, nil, ErrPGPVerification
	}
	until := keyExpiry(nil, e.PrimaryKey, self)
	if direct, err := e.LatestValidDirectSignature(now, pgpConfig(now)); err == nil {
		until = keyExpiry(until, e.PrimaryKey, direct)
	}
	return e, until, nil
}
func ParsePGPPublicKey(ctx context.Context, wire []byte, expected string, now time.Time) (*PGPPublicKey, error) {
	return parsePGPPublicKey(ctx, wire, expected, now, false)
}
func parsePGPPublicKey(ctx context.Context, wire []byte, expected string, now time.Time, recipient bool) (*PGPPublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected = strings.ToLower(expected)
	if len(expected) != 40 && len(expected) != 64 {
		return nil, ErrPGPInput
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return nil, ErrPGPInput
	}
	data, err := pgpBinary(wire, "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return nil, err
	}
	defer Clear(data)
	e, until, err := readPGPEntity(data, now)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(e.PrimaryKey.Fingerprint) != expected {
		return nil, ErrPGPVerification
	}
	var encryption *PGPRecipient
	if recipient {
		encryption, until, err = pgpRecipient(e, now, until)
		if err != nil {
			return nil, err
		}
	} else if _, ok := e.SigningKey(now, pgpConfig(now)); !ok {
		return nil, ErrPGPVerification
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	algorithm, _ := pgpAlgorithm(e.PrimaryKey)
	key := &PGPPublicKey{Schema: 1, Packets: bytes.Clone(data), Fingerprint: expected, Algorithm: algorithm, Version: e.PrimaryKey.Version, Created: e.PrimaryKey.CreationTime.UTC(), ValidUntil: until, Recipient: encryption}
	if recipient {
		key.Purpose = "encrypt"
	}
	return key, nil
}
func InspectPGPSignature(wire []byte) error {
	data, err := pgpBinary(wire, "PGP SIGNATURE")
	if err != nil {
		return err
	}
	defer Clear(data)
	if err = pgpFraming(data, true); err != nil {
		return err
	}
	p, err := packet.Read(bytes.NewReader(data))
	if err != nil {
		return ErrPGPInput
	}
	sig, ok := p.(*packet.Signature)
	if !ok || sig.SigType != packet.SigTypeBinary || (sig.Hash != crypto.SHA256 && sig.Hash != crypto.SHA384 && sig.Hash != crypto.SHA512) {
		return ErrPGPInput
	}
	return nil
}

type pgpSource struct {
	ctx    context.Context
	reader io.Reader
	count  int64
	hash   io.Writer
}

func (r *pgpSource) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) > 32<<10 {
		p = p[:32<<10]
	}
	n, err := r.reader.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
		r.count += int64(n)
	}
	return n, err
}

// VerifyPGPDetached accepts only one detached binary-document signature. The
// caller supplies the approved primary fingerprint and exact accepted bytes.
func VerifyPGPDetached(ctx context.Context, key PGPPublicKey, wire []byte, source io.Reader, size int64, digest string, now time.Time, maxAge uint32) (*PGPVerification, error) {
	if key.Purpose != "" || size < 0 || size > 1<<30 || now.IsZero() || InspectPGPSignature(wire) != nil {
		return nil, ErrPGPInput
	}
	e, until, err := readPGPEntity(key.Packets, now)
	if err != nil {
		return nil, err
	}
	if hex.EncodeToString(e.PrimaryKey.Fingerprint) != key.Fingerprint {
		return nil, ErrPGPVerification
	}
	if key.ValidUntil != nil {
		until = earlier(until, *key.ValidUntil)
	}
	data, err := pgpBinary(wire, "PGP SIGNATURE")
	if err != nil {
		return nil, err
	}
	defer Clear(data)
	h := NewDigest()
	input := &pgpSource{ctx: ctx, reader: io.LimitReader(source, size+1), hash: h}
	md, err := openpgp.VerifyDetachedSignatureReader(openpgp.EntityList{e}, input, bytes.NewReader(data), pgpConfig(now))
	if err != nil {
		return nil, ErrPGPVerification
	}
	if _, err = io.CopyBuffer(io.Discard, md.UnverifiedBody, make([]byte, 32<<10)); err != nil {
		return nil, err
	}
	if !md.IsVerified || md.SignatureError != nil || md.Signature == nil || md.SignedBy == nil || input.count != size || hex.EncodeToString(h.Sum(nil)) != digest {
		return nil, ErrPGPVerification
	}
	sig, signer := md.Signature, md.SignedBy
	if sig.CreationTime.After(now) || sig.SigType != packet.SigTypeBinary {
		return nil, ErrPGPVerification
	}
	if _, ok := pgpAlgorithm(signer.PublicKey); !ok {
		return nil, ErrPGPVerification
	}
	until = keyExpiry(until, signer.PublicKey, signer.SelfSignature)
	if sig.SigLifetimeSecs != nil && *sig.SigLifetimeSecs > 0 {
		until = earlier(until, sig.CreationTime.Add(time.Duration(*sig.SigLifetimeSecs)*time.Second))
	}
	if maxAge > 0 {
		until = earlier(until, sig.CreationTime.Add(time.Duration(maxAge)*time.Second))
	}
	if until != nil && !now.Before(*until) {
		return nil, ErrPGPVerification
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return &PGPVerification{Backend: PGPBackend, PrimaryFingerprint: key.Fingerprint, SignerFingerprint: hex.EncodeToString(signer.PublicKey.Fingerprint), SignatureSHA256: Digest(wire), Hash: sig.Hash.String(), SignatureVersion: sig.Version, Created: sig.CreationTime.UTC(), VerifiedAt: now.UTC(), ValidUntil: until}, nil
}
