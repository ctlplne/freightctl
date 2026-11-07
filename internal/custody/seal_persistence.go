package custody

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

const sealEAName = "FREIGHTCTL.SEAL.V1"
const maximumSealRecord = 512

// This is a filesystem completion record,not a domain receipt or permission.
// Windows attaches it to the exact file only after its data flush succeeds.
// Its physical identity prevents a copied record from qualifying a replacement.
type sealRecord struct {
	Schema int    `json:"schema_version"`
	Store  string `json:"storage_id"`
	Object string `json:"object_name"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
	Volume uint64 `json:"volume_serial"`
	FileID string `json:"file_id"`
}

var sealFileID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validSealRecord(p sealRecord) bool {
	return p.Schema == 1 && store.ValidID(p.Store) && validName(p.Object) && p.Size >= 0 && digestPattern.MatchString(p.SHA256) && sealFileID.MatchString(p.FileID) && p.FileID != strings.Repeat("0", 32)
}
func encodeSealRecord(p sealRecord) ([]byte, error) {
	if !validSealRecord(p) {
		return nil, ErrIntegrity
	}
	wire, err := json.Marshal(p)
	if err != nil || len(wire) > maximumSealRecord {
		return nil, ErrIntegrity
	}
	return wire, nil
}
func validateSealRecord(raw []byte, expected sealRecord) error {
	if len(raw) == 0 || len(raw) > maximumSealRecord {
		return ErrIntegrity
	}
	var p sealRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&p) != nil || d.Decode(&tail) != io.EOF || !validSealRecord(p) {
		return ErrIntegrity
	}
	canonical, err := encodeSealRecord(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrIntegrity
	}
	// Empty expected digest is used only by metadata slot observation. Actual
	// verification always supplies and hashes the exact approved byte digest.
	if expected.SHA256 == "" {
		expected.SHA256 = p.SHA256
	}
	if p != expected {
		return ErrIntegrity
	}
	return nil
}

func encodeSealEA(value []byte) ([]byte, error) {
	if len(value) > maximumSealRecord {
		return nil, ErrIntegrity
	}
	b := make([]byte, 8+len(sealEAName)+1+len(value))
	b[5] = byte(len(sealEAName))
	binary.LittleEndian.PutUint16(b[6:8], uint16(len(value)))
	copy(b[8:], sealEAName)
	copy(b[8+len(sealEAName)+1:], value)
	return b, nil
}
func decodeSealEA(b []byte) ([]byte, error) {
	nameEnd := 8 + len(sealEAName)
	if len(b) < nameEnd+1 || binary.LittleEndian.Uint32(b[:4]) != 0 || b[4] != 0 || int(b[5]) != len(sealEAName) || string(b[8:nameEnd]) != sealEAName || b[nameEnd] != 0 {
		return nil, ErrIntegrity
	}
	n := int(binary.LittleEndian.Uint16(b[6:8]))
	end := nameEnd + 1 + n
	if n > maximumSealRecord || end > len(b) || len(b) != end && len(b) != (end+3)&^3 {
		return nil, ErrIntegrity
	}
	for _, padding := range b[end:] {
		if padding != 0 {
			return nil, ErrIntegrity
		}
	}
	if n == 0 { // The native query may represent an absent EA with an empty value.
		return nil, nil
	}
	return b[nameEnd+1 : end], nil
}

// Keep this ordering in one place:seal,flush the original writable handle,
// record platform completion,close,and persist the directory before acceptance.
func (d *Disk) sealObject(f *os.File, name string, size int64, digest string) error {
	if !validName(name) || size < 0 || !digestPattern.MatchString(digest) {
		return ErrInput
	}
	if err := protectedfs.SealReadOnly(f); err != nil {
		return err
	}
	if err := persistCreatedSeal(f, d.identity, name, size, digest); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return d.sync()
}
