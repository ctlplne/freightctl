//go:build !windows

package protectedfs

import "os"

func platformProtection(_ *os.File, info os.FileInfo) (ProtectionState, error) {
	switch info.Mode().Perm() {
	case 0600:
		return PrivateWritable, nil
	case 0400:
		return PrivateSealed, nil
	default:
		return 0, ErrPrivacy
	}
}

func platformSeal(f *os.File) error { return f.Chmod(0400) }
