//go:build integration

package crypto

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// NativeProofHTPasswd prepares a protected independent-peer fixture,not an
// application credential database. BCrypt's72-byte input limit is algorithmic;
// the ordinary HTTPS Basic credential profile retains its separate file bound.
func NativeProofHTPasswd(user string, password *Secret) (*Secret, error) {
	if !ftpsText(user, 256) || strings.Contains(user, ":") || password == nil || len(password.Bytes) < 1 || len(password.Bytes) > 72 || !ftpsText(string(password.Bytes), 72) {
		return nil, errors.New("invalid native htpasswd fixture")
	}
	hash, err := bcrypt.GenerateFromPassword(password.Bytes, bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("native htpasswd fixture failed")
	}
	defer Clear(hash)
	line := make([]byte, len(user)+1+len(hash)+1)
	copy(line, user)
	line[len(user)] = ':'
	copy(line[len(user)+1:], hash)
	line[len(line)-1] = '\n'
	return ProtectBytes(line), nil
}
