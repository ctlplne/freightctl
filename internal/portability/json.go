package portability

import (
	"context"
	"encoding/json"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

type JSONExportReceipt[Source any] struct {
	Source Source `json:"source"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size_bytes"`
}

// WritePreparedJSON writes protected staging bytes, then checks current
// authority and commits a preparation event for their exact checksum.
func WritePreparedJSON[Source any](ctx context.Context, tx *store.Transaction, event, resource string, source Source, manifest any, output io.Writer) (*JSONExportReceipt[Source], error) {
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	payload = append(payload, '\n')
	if len(payload) > 48<<10 {
		return nil, store.ErrLimit
	}
	written, err := output.Write(payload)
	if err != nil {
		return nil, err
	}
	if written != len(payload) {
		return nil, io.ErrShortWrite
	}
	if err = tx.Reauthorize(ctx); err != nil {
		return nil, err
	}
	receipt := &JSONExportReceipt[Source]{Source: source, SHA256: secure.Digest(payload), Size: written}
	if _, err = tx.Append(ctx, event, resource, receipt); err != nil {
		return nil, err
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return receipt, nil
}
