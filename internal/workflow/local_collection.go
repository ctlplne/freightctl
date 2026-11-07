package workflow

import secure "github.com/ctlplne/freightctl/internal/crypto"

func collectionSourceIdentity(connection ConnectionView) string {
	if connection.Local != nil {
		return secure.Digest([]byte("local-root-v1:" + connection.ID + ":" + connection.Local.RootFingerprint))
	}
	return secure.Digest([]byte(connection.ID + ":" + connection.Directory))
}
