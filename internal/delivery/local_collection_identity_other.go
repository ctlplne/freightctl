//go:build !darwin && !linux && !windows

package delivery

import "os"

func localCollectionRootIdentity(_ *os.File) (string, error) { return "", ErrLocalSource }
