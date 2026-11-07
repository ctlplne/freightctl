package protectedfs

import (
	"errors"
	"os"
	"strings"
)

// CreateDirectoryExclusive never adopts or changes an existing directory. The
// Windows owner-only descriptor is attached as part of directory creation.
func CreateDirectoryExclusive(path string) (*os.File, error) {
	f, err := platformDirectory(path)
	if err != nil {
		return nil, err
	}
	if err = ValidateDirectory(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func privateLeaf(name string) bool {
	if name == "" || len(name) > 255 || name == "." || name == ".." || strings.HasSuffix(name, ".") {
		return false
	}
	for _, b := range []byte(name) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '-' || b == '_') {
			return false
		}
	}
	return !reservedLeaf(name)
}

func reservedLeaf(name string) bool {
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

// CreateAt exclusively creates one private flat object relative to the held
// root. It never reconstructs the root pathname or follows a leaf reparse point.
func CreateAt(root *os.Root, name string) (*os.File, error) {
	if root == nil || !privateLeaf(name) {
		return nil, ErrPrivacy
	}
	f, err := platformCreateAt(root, name)
	if err != nil {
		return nil, err
	}
	if err = ValidateFile(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
