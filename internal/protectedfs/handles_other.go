//go:build !windows

package protectedfs

import "os"

func platformPrivacy(_ *os.File, info os.FileInfo, _ bool) error {
	if info.Mode().Perm()&0077 != 0 {
		return ErrPrivacy
	}
	return nil
}
func platformPublic(_ *os.File, info os.FileInfo) error {
	if info.Mode().Perm()&0022 != 0 {
		return ErrPrivacy
	}
	return nil
}
func platformCreate(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}
