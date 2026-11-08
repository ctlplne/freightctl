package delivery

import (
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"path"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// DAVCollectionSource is read-only. It cannot be used as a delivery endpoint.
type DAVCollectionSource struct {
	Schema      int                         `json:"schema_version"`
	Destination secure.HTTPSReadDestination `json:"destination"`
}

func (d *DAVCollectionSource) Valid() bool {
	return d != nil && d.Schema == 1 && secure.ValidateHTTPSReadDestination(d.Destination) == nil
}

type davCollectionReader interface {
	Get(context.Context, string) (*secure.HTTPSReadResponse, error)
	Close() error
}

type DAVCollectionPeer struct {
	client    davCollectionReader
	directory string
}

func OpenDAVCollectionPeer(ctx context.Context, definition *DAVCollectionSource, directory string, check func() error) (*DAVCollectionPeer, error) {
	canonical, err := vpath.Canonical(directory)
	if !definition.Valid() || check == nil || err != nil || canonical != directory || vpath.ControlPath(directory) {
		return nil, ErrInput
	}
	client, err := secure.NewHTTPSReadClient(ctx, definition.Destination, check)
	if err != nil {
		return nil, err
	}
	return &DAVCollectionPeer{client: client, directory: directory}, nil
}

func (p *DAVCollectionPeer) Close() error { return p.client.Close() }

func (p *DAVCollectionPeer) get(ctx context.Context, name string, check func() error) (*secure.HTTPSReadResponse, error) {
	if check == nil || !collectionName.MatchString(name) {
		return nil, ErrInput
	}
	if err := collectionReadGuard(ctx, check); err != nil {
		return nil, err
	}
	response, err := p.client.Get(ctx, path.Join(p.directory, name))
	if err != nil {
		return nil, err
	}
	if response == nil || response.Body == nil {
		return nil, ErrInput
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Range") != "" || (response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity") {
		response.Body.Close()
		return nil, ErrInput
	}
	return response, nil
}

func (p *DAVCollectionPeer) ReadManifest(ctx context.Context, name string, check func() error) ([]byte, error) {
	response, err := p.get(ctx, name, check)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength == 0 || response.ContentLength > 32<<10 {
		return nil, ErrInput
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil || len(data) < 1 || len(data) > 32<<10 || (response.ContentLength >= 0 && int64(len(data)) != response.ContentLength) {
		secure.Clear(data)
		return nil, ErrInput
	}
	if err = collectionReadGuard(ctx, check); err != nil {
		secure.Clear(data)
		return nil, err
	}
	if err = response.Body.Close(); err != nil {
		secure.Clear(data)
		return nil, err
	}
	return data, nil
}

// Output is private caller-owned staging. Only the ordinary workflow may commit
// exact custody,events and approved onward intents after every input verifies.
func (p *DAVCollectionPeer) CopyVerified(ctx context.Context, name string, size int64, digest string, output io.Writer, check func() error) error {
	if check == nil || output == nil || size < 0 || size > 1<<30 || len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return ErrInput
	}
	response, err := p.get(ctx, name, check)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != size {
		return ErrInput
	}
	hash := secure.NewDigest()
	buffer := make([]byte, 32<<10)
	for copied := int64(0); copied < size; {
		if err = collectionReadGuard(ctx, check); err != nil {
			return err
		}
		n, err := io.ReadFull(response.Body, buffer[:min(int64(len(buffer)), size-copied)])
		if err != nil {
			return err
		}
		hash.Write(buffer[:n])
		written, err := (collectionCheckedWriter{ctx, check, output}).Write(buffer[:n])
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrShortWrite
		}
		copied += int64(n)
	}
	var tail [1]byte
	if n, err := response.Body.Read(tail[:]); n != 0 || err != io.EOF || hex.EncodeToString(hash.Sum(nil)) != digest {
		return ErrInput
	}
	if err = collectionReadGuard(ctx, check); err != nil {
		return err
	}
	return response.Body.Close()
}
