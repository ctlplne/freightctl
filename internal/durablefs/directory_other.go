//go:build !windows

package durablefs

import "os"

func syncDirectory(directory *os.File) error {
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return ErrDirectoryIdentity
	}
	return directory.Sync()
}
