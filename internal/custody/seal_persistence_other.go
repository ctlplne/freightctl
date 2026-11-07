//go:build !windows

package custody

import "os"

func persistCreatedSeal(f *os.File, _, _ string, _ int64, _ string) error { return f.Sync() }
func checkSealPersistence(_ *os.File, _, _ string, _ int64, _ string) (bool, error) {
	return true, nil
}
func recoverSealPersistence(f *os.File, _, _ string, _ int64, _ string) error { return f.Sync() }
