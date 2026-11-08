package workflow

import (
	"context"
	"io"
	"reflect"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
)

type collectionReadPeer interface {
	Close() error
	ReadManifest(context.Context, string, func() error) ([]byte, error)
	CopyVerified(context.Context, string, int64, string, io.Writer, func() error) error
}

func openCollectionSourcePeer(ctx context.Context, connection *ConnectionDefinition, kind string, check func() error) (collectionReadPeer, error) {
	if connection == nil || check == nil {
		return nil, ErrInput
	}
	// A nil concrete pointer inside an interface is not a nil interface. On
	// refusal return no reader,so ordinary worker cleanup cannot dereference one.
	switch kind {
	case "sftp.collect":
		if connection.Schema == 1 && connection.DAV == nil && connection.FTPS == nil && connection.Local == nil {
			peer, err := delivery.OpenCollectionPeer(ctx, connection.Destination, connection.Directory, check)
			if err != nil {
				return nil, err
			}
			return peer, nil
		}
	case "ftps.collect":
		if connection.Schema == 2 && connection.DAV == nil && connection.Local == nil && reflect.DeepEqual(connection.Destination, secure.SSHDestination{}) && connection.FTPS.Valid(connection.Directory) {
			peer, err := delivery.OpenFTPSCollectionPeer(ctx, connection.FTPS.Destination, connection.Directory, check)
			if err != nil {
				return nil, err
			}
			return peer, nil
		}
	case "local.collect":
		if connection.Schema == 3 && connection.DAV == nil && connection.FTPS == nil && reflect.DeepEqual(connection.Destination, secure.SSHDestination{}) && connection.Directory == "/" && connection.Local.Valid() {
			peer, err := delivery.OpenConfiguredLocalCollectionPeer(ctx, connection.Local, check)
			if err != nil {
				return nil, err
			}
			return peer, nil
		}
	case "webdav.collect":
		if connection.Schema == 4 && connection.Local == nil && connection.FTPS == nil && reflect.DeepEqual(connection.Destination, secure.SSHDestination{}) && connection.DAV.Valid() {
			peer, err := delivery.OpenDAVCollectionPeer(ctx, connection.DAV, connection.Directory, check)
			if err != nil {
				return nil, err
			}
			return peer, nil
		}
	}
	return nil, ErrInput
}
