package delivery

import (
	"context"
	"path"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

// ObserveSFTP only opens and hashes the exact named final file. Its bounded
// stream exposes no bytes to callers and has no write/publication operation.
func ObserveSFTP(ctx context.Context, destination secure.SSHDestination, directory, name, sha256 string, size int64, check func() error) bool {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if size < 0 || path.Base(name) != name || name == "." || name == ".." || ctx.Err() != nil {
		return false
	}
	if err := check(); err != nil {
		return false
	}
	spec := &Definition{Destination: destination, Directory: directory}
	spec.Source.Size = size
	spec.Source.SHA256 = sha256
	client, stream, err := connect(ctx, spec)
	if err != nil {
		return false
	}
	defer stream.Close()
	defer client.Close()
	if err = check(); err != nil {
		return false
	}
	if remoteDirectory(client, directory) != nil {
		return false
	}
	return verifyRemote(ctx, client, path.Join(directory, name), spec, check) == nil && check() == nil
}
