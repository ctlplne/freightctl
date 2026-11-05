package workflow

import (
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

// Share the exact native mixed fixture with a cheap typed-parser contract.
// This opens no database, source, receiver, scanner or recipient key.
func mixedFTPSCollectionSteps(ssh, ftp Reference, policy *store.EncryptionPolicy) []Step {
	return []Step{
		{ID: "stock_ssh", Kind: "sftp.deliver", Connection: ssh, Filename: "collected.csv"},
		{ID: "encrypted_ftp", Kind: "ftps.deliver", Connection: ftp, Filename: "collected.pgp", Encryption: policy},
	}
}

func TestMixedFTPSCollectionStepContract(t *testing.T) {
	ssh := Reference{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}
	ftp := Reference{ID: "00000000-0000-0000-0000-000000000002", Version: 1, Hash: strings.Repeat("b", 64)}
	policy := &store.EncryptionPolicy{Key: store.PGPReference{ID: "00000000-0000-0000-0000-000000000003", Version: 1, Hash: strings.Repeat("c", 64)}, Profile: secure.PGPEncryptMDC}
	d := Definition{Schema: 1, Name: "Mixed collected settlement", Steps: mixedFTPSCollectionSteps(ssh, ftp, policy)}
	normalized, err := Normalize(d)
	if err != nil {
		t.Fatal("exact mixed fixture must satisfy existing step grammar", err)
	}
	if len(normalized.Steps) != 2 || normalized.Steps[0].Connection != ssh || normalized.Steps[0].Encryption != nil || normalized.Steps[1].Connection != ftp || normalized.Steps[1].Encryption == policy || *normalized.Steps[1].Encryption != *policy {
		t.Fatal("mixed fixture changed ordered receiver or encryption meaning")
	}
	for index, invalid := range []string{"stock-ssh", "encrypted-ftp"} {
		changed := Definition{Schema: 1, Name: d.Name, Steps: mixedFTPSCollectionSteps(ssh, ftp, policy)}
		changed.Steps[index].ID = invalid
		if _, err := Normalize(changed); !errors.Is(err, ErrInput) {
			t.Fatal("old hyphenated fixture ID bypassed original typed grammar", err)
		}
	}
}
