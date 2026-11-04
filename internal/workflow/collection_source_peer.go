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
	switch kind {
	case "sftp.collect":
		if connection.Schema == 1 && connection.FTPS == nil {
			return delivery.OpenCollectionPeer(ctx, connection.Destination, connection.Directory, check)
		}
	case "ftps.collect":
		if connection.Schema == 2 && reflect.DeepEqual(connection.Destination, secure.SSHDestination{}) && connection.FTPS.Valid(connection.Directory) {
			return delivery.OpenFTPSCollectionPeer(ctx, connection.FTPS.Destination, connection.Directory, check)
		}
	}
	return nil, ErrInput
}
