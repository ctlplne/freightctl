//go:build !linux && !darwin

package crypto

// Native platform protection and qualification remain open.
func protect([]byte) bool { return false }
func unprotect([]byte)    {}
