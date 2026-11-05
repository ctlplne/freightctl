// Package durablefs keeps filesystem persistence behind explicit owned handles.
package durablefs

import (
	"errors"
	"os"
)

var ErrDirectoryIdentity = errors.New("directory identity cannot be preserved for persistence")

// SyncDirectory flushes the exact directory represented by directory. The
// caller keeps ownership of the input file and must keep it open throughout
// this call. An unsupported filesystem or failed identity/flush/close check is
// an error; success is not independent crash or power-loss qualification.
func SyncDirectory(directory *os.File) error {
	if directory == nil {
		return os.ErrInvalid
	}
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrDirectoryIdentity
	}
	return syncDirectory(directory)
}
