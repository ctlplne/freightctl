package crypto

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
)

func pgpFixture(t testing.TB, v6 bool) (*openpgp.Entity, []byte, []byte, []byte, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	created := now.Add(-time.Hour)
	algo := packet.PubKeyAlgoEdDSA
	if v6 {
		algo = packet.PubKeyAlgoEd25519
	}
	config := &packet.Config{Algorithm: algo, V6Keys: v6, Time: func() time.Time { return created }, DefaultHash: crypto.SHA256, KeyLifetimeSecs: 86400}
	entity, err := openpgp.NewEntity("freightctl synthetic signer", "", "", config)
	if err != nil {
		t.Fatal(err)
	}
	var public, signature bytes.Buffer
	if err = entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	source := []byte("account,amount\r\n00001,1.01\r\n")
	config.Time = func() time.Time { return now.Add(-time.Minute) }
	if err = openpgp.DetachSign(&signature, []*openpgp.Entity{entity}, bytes.NewReader(source), config); err != nil {
		t.Fatal(err)
	}
	return entity, public.Bytes(), signature.Bytes(), source, now
}
func TestPGPDetachedExactBytesIdentityAndTime(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		entity, public, signature, source, now := pgpFixture(t, v6)
		fingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
		key, err := ParsePGPPublicKey(context.Background(), public, strings.ToUpper(fingerprint), now)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := VerifyPGPDetached(context.Background(), *key, signature, bytes.NewReader(source), int64(len(source)), Digest(source), now, 3600)
		if err != nil || verified.PrimaryFingerprint != fingerprint || verified.SignatureSHA256 != Digest(signature) || verified.ValidUntil == nil {
			t.Fatal(verified, err)
		}
		if _, err = VerifyPGPDetached(context.Background(), *key, signature, bytes.NewReader(bytes.ReplaceAll(source, []byte("\r\n"), []byte("\n"))), int64(len(source)), Digest(source), now, 0); err == nil {
			t.Fatal("normalized line endings bypassed exact binary signature")
		}
		if _, err = VerifyPGPDetached(context.Background(), *key, signature, bytes.NewReader(append(bytes.Clone(source), 'x')), int64(len(source))+1, Digest(append(bytes.Clone(source), 'x')), now, 0); err == nil {
			t.Fatal("modified signed bytes accepted")
		}
		if _, err = ParsePGPPublicKey(context.Background(), public, strings.Repeat("0", len(fingerprint)), now); err == nil {
			t.Fatal("wrong primary fingerprint accepted")
		}
		if _, err = VerifyPGPDetached(context.Background(), *key, signature, bytes.NewReader(source), int64(len(source)), Digest(source), now.Add(2*time.Hour), 60); err == nil {
			t.Fatal("expired signature-age policy accepted")
		}
		if _, err = ParsePGPPublicKey(context.Background(), public, fingerprint, now.Add(48*time.Hour)); err == nil {
			t.Fatal("expired key accepted")
		}
		if InspectPGPSignature(append(bytes.Clone(signature), signature...)) == nil {
			t.Fatal("multiple signatures accepted")
		}
	}
}
func TestPGPFramingRejectsSecretsCompressionAndOversizedPackets(t *testing.T) {
	for _, wire := range [][]byte{{0xc5, 1, 4}, {0xc7, 1, 4}, {0xc8, 1, 4}, {0xcb, 1, 4}, {0xc2, 255, 255, 255, 255, 255}, {0xc2, 224, 4}, {0x8f, 4}, {0xc2, 1, 5}} {
		if pgpFraming(wire, true) == nil || pgpFraming(wire, false) == nil {
			t.Fatalf("unsafe packet accepted: %x", wire)
		}
	}
	if _, err := pgpBinary([]byte("-----BEGIN PGP PRIVATE KEY BLOCK-----\nopaque\n-----END PGP PRIVATE KEY BLOCK-----"), "PGP PUBLIC KEY BLOCK"); err == nil {
		t.Fatal("private armor decoded")
	}
	if _, err := pgpBinary(bytes.Repeat([]byte("x"), MaxPGPWire+1), "PGP SIGNATURE"); err == nil {
		t.Fatal("unbounded wire accepted")
	}
}
func FuzzPGPAdmission(f *testing.F) {
	_, key, signature, _, _ := pgpFixture(f, false)
	f.Add(key)
	f.Add(signature)
	f.Add([]byte{0xc2, 255, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxPGPWire+1 {
			return
		}
		_ = pgpFraming(data, true)
		_ = pgpFraming(data, false)
		_ = InspectPGPSignature(data)
		_, _ = ParsePGPPublicKey(context.Background(), data, strings.Repeat("0", 40), time.Unix(1793220619, 0))
		_, _ = ParsePGPRecipient(context.Background(), data, strings.Repeat("0", 40), time.Unix(1793220619, 0))
	})
}
