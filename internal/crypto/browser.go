package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

func protectedHexMAC(key []byte, parts ...string) *Secret {
	h := hmac.New(sha256.New, key)
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
	}
	sum := h.Sum(nil)
	defer Clear(sum)
	out := make([]byte, hex.EncodedLen(len(sum)))
	hex.Encode(out, sum)
	s := &Secret{Bytes: out}
	s.Locked = protect(out)
	return s
}

// BrowserSessionToken derives a purpose-separated credential using the
// authenticated random service credential as the HMAC key. A command replay
// regenerates the same token without persisting a plaintext secret or renewing
// its database expiry. A weak/repeated operation key cannot weaken the MAC key.
func BrowserSessionToken(credential []byte, tenant, partner, operationKey string) (*Secret, error) {
	if len(credential) != 64 || len(tenant) != 36 || len(partner) != 36 || len(operationKey) < 1 || len(operationKey) > 128 {
		return nil, errors.New("invalid browser credential input")
	}
	for _, b := range credential {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return nil, errors.New("invalid browser credential input")
		}
	}
	return protectedHexMAC(credential, "freightctl.browser.session.v1\x00", tenant, "\x00", partner, "\x00", operationKey), nil
}

func BrowserCSRFToken(session []byte) (*Secret, error) {
	if len(session) != 64 {
		return nil, errors.New("invalid browser session input")
	}
	return protectedHexMAC(session, "freightctl.browser.csrf.v1"), nil
}

func EqualToken(a, b []byte) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare(a, b) == 1
}
