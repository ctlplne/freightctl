package store

import (
	"context"
	"encoding/json"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// This is a requested exact source, not a grant. The transaction independently
// resolves the stored view and current recipient before it opens any bytes.
type ExchangeCopyOrigin struct {
	ExchangeID  string           `json:"exchange_id"`
	RequestHash string           `json:"request_hash"`
	Artifact    ExchangeArtifact `json:"artifact"`
}

type ExchangeCopyRequest struct {
	ExchangeCopyOrigin
	Path string `json:"virtual_path"`
}

func ValidateExchangeCopy(r ExchangeCopyRequest, maximum int64) error {
	p, err := vpath.Canonical(r.Path)
	if maximum < 0 || !ValidID(r.ExchangeID) || !browserSecretHash.MatchString(r.RequestHash) || !ValidID(r.Artifact.ID) || r.Artifact.Size < 0 || r.Artifact.Size > maximum || !browserSecretHash.MatchString(r.Artifact.SHA256) || len(r.Artifact.Policy) < 1 || len(r.Artifact.Policy) > 256 || err != nil || p != r.Path || p == "/" || vpath.ControlPath(p) {
		return ErrExchangeInput
	}
	return nil
}

// The root-resolved ordinary create request is included: a different receive
// view, source identity, policy, digest or destination cannot replay this key.
func ExchangeCopyMeaning(r ExchangeCopyRequest, ordinaryMeaning string) string {
	wire, _ := json.Marshal(struct {
		Profile string              `json:"profile"`
		Request ExchangeCopyRequest `json:"request"`
		Target  string              `json:"ordinary_target_meaning"`
	}{"received-artifact-copy-v1", r, ordinaryMeaning})
	return secure.Digest(wire)
}

func (t *Transaction) AcceptExchangeCopy(ctx context.Context, key, meaning string, f *File, storageID string, origin ExchangeCopyOrigin) error {
	if !ValidID(storageID) || !ValidID(origin.ExchangeID) || !browserSecretHash.MatchString(origin.RequestHash) || origin.Artifact.ID == f.ID || origin.Artifact.Size != f.Size || origin.Artifact.SHA256 != f.SHA256 {
		return ErrIsolation
	}
	return t.accept(ctx, key, meaning, f, "", storageID, &origin)
}
