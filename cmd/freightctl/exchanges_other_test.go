//go:build !windows

package main

import "testing"

func TestExchangeDownloadDirectoryReplacementDuringWriteCannotSubstituteOutput(t *testing.T) {
	exchangeDownloadDirectoryReplacementDuringWrite(t)
}
