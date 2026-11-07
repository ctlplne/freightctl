package protectedfs

import (
	"errors"
	"os"
)

func validate(f *os.File, directory bool) error {
	if f == nil {
		return ErrPrivacy
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrPrivacy
	}
	return platformPrivacy(f, info, directory)
}

// ValidateFile checks the opened object,not a name that can be replaced.
func ValidateFile(f *os.File) error      { return validate(f, false) }
func ValidateDirectory(f *os.File) error { return validate(f, true) }

// CreateExclusive never overwrites an existing object. Windows attaches the
// owner-only protected descriptor at creation,before any secret bytes are sent.
func CreateExclusive(path string) (*os.File, error) {
	f, err := platformCreate(path)
	if err != nil {
		return nil, err
	}
	if err = ValidateFile(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
