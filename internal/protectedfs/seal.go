package protectedfs

import "os"

type ProtectionState uint8

const (
	PrivateWritable ProtectionState = iota + 1
	PrivateSealed
)

// Protection recognizes only private writable staging or private sealed bytes.
// It does not assert a content hash,persistence,approval or domain acceptance.
func Protection(f *os.File) (ProtectionState, error) {
	if f == nil {
		return 0, ErrPrivacy
	}
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, ErrPrivacy
	}
	return platformProtection(f, info)
}

// SealReadOnly removes byte-write grants. Like Unix chmod,it cannot revoke an
// already-open writable handle. The owner must sync and close that handle before
// publication. Windows retains owner metadata rights needed for atomic linking.
func SealReadOnly(f *os.File) error {
	state, err := Protection(f)
	if err != nil {
		return err
	}
	if state == PrivateSealed {
		return nil
	}
	if err = platformSeal(f); err != nil {
		return err
	}
	state, err = Protection(f)
	if err != nil {
		return err
	}
	if state != PrivateSealed {
		return ErrPrivacy
	}
	return nil
}
