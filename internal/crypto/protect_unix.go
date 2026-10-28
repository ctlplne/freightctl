//go:build linux || darwin

package crypto

import "golang.org/x/sys/unix"

func protect(b []byte) bool { return unix.Mlock(b) == nil }
func unprotect(b []byte)    { _ = unix.Munlock(b) }
