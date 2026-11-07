//go:build !windows

package protectedfs

import "os"

func platformDirectory(path string) (*os.File, error) {
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() {
		return nil, ErrPrivacy
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		f.Close()
		return nil, ErrPrivacy
	}
	return f, nil
}

func platformCreateAt(root *os.Root, name string) (*os.File, error) {
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	if err = ValidateDirectory(directory); err != nil {
		return nil, err
	}
	return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
}
