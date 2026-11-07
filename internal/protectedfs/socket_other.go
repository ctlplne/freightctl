//go:build !windows

package protectedfs

import "os"

func platformSocket(_ string, info os.FileInfo) (*os.File, error) {
	return nil, platformSocketPrivacy(nil, info)
}

func platformSocketPrivacy(_ *os.File, info os.FileInfo) error {
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 {
		return ErrPrivacy
	}
	return nil
}
