package delivery

import (
	"context"
	"encoding/hex"
	"io"
	"path"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/ftpsclient"
	"github.com/ctlplne/freightctl/internal/vpath"
)

// A collector cannot acquire upload, rename, delete, arbitrary-command or active
// data-channel methods through this interface. Domain admission remains the
// workflow's job, not a transport capability granted by opening this peer.
type ftpsCollectionReader interface {
	Close() error
	ReadBounded(string, int64) ([]byte, error)
	RetrieveToStage(string, io.Writer, int64, string) error
}

type FTPSCollectionPeer struct {
	client    ftpsCollectionReader
	directory string
}

func OpenFTPSCollectionPeer(ctx context.Context, destination secure.FTPSDestination, directory string, check func() error) (*FTPSCollectionPeer, error) {
	canonical, err := vpath.Canonical(directory)
	if check == nil || err != nil || canonical != directory || vpath.ControlPath(directory) {
		return nil, ErrInput
	}
	client, err := ftpsclient.New(ctx, destination, check)
	if err != nil {
		return nil, err
	}
	return &FTPSCollectionPeer{client: client, directory: directory}, nil
}

func (p *FTPSCollectionPeer) Close() error { return p.client.Close() }

func collectionReadGuard(ctx context.Context, check func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := check(); err != nil {
		return err
	}
	return ctx.Err()
}

func (p *FTPSCollectionPeer) ReadManifest(ctx context.Context, name string, check func() error) ([]byte, error) {
	if check == nil || !collectionName.MatchString(name) {
		return nil, ErrInput
	}
	if err := collectionReadGuard(ctx, check); err != nil {
		return nil, err
	}
	// A caller's shorter operation context must interrupt a blocked read even
	// when the session was opened with a longer root context.
	stop := context.AfterFunc(ctx, func() { p.client.Close() })
	defer stop()
	data, err := p.client.ReadBounded(path.Join(p.directory, name), ftpsclient.MaxMetadata)
	if err == nil {
		err = collectionReadGuard(ctx, check)
	}
	if err != nil || int64(len(data)) > ftpsclient.MaxMetadata {
		secure.Clear(data)
		if err == nil {
			err = ErrInput
		}
		return nil, err
	}
	return data, nil
}

type collectionCheckedWriter struct {
	ctx    context.Context
	check  func() error
	output io.Writer
}

func (w collectionCheckedWriter) Write(data []byte) (int, error) {
	if err := collectionReadGuard(w.ctx, w.check); err != nil {
		return 0, err
	}
	return w.output.Write(data)
}

// CopyVerified writes only to caller-owned private staging. The transport checks
// exact bytes/digest, EOF and final reply; caller capacity/lease guards also run
// before every write and after completion. No local publication is authorized.
func (p *FTPSCollectionPeer) CopyVerified(ctx context.Context, name string, size int64, digest string, output io.Writer, check func() error) error {
	if check == nil || output == nil || !collectionName.MatchString(name) || size < 0 || size > ftpsclient.MaxFile || len(digest) != 64 || strings.ToLower(digest) != digest {
		return ErrInput
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return ErrInput
	}
	if err := collectionReadGuard(ctx, check); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { p.client.Close() })
	defer stop()
	if err := p.client.RetrieveToStage(path.Join(p.directory, name), collectionCheckedWriter{ctx, check, output}, size, digest); err != nil {
		return err
	}
	return collectionReadGuard(ctx, check)
}
