//go:build integration && davpeer

package api

import (
	"encoding/json"
	"fmt"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type nativeDAVStockPeer struct {
	Binary, Commit, ManifestSHA256, BinarySHA256, PrivateDirectory string
}

// Share the original complete identity and enforcing-gate checks with the
// independent stock-server proof. No alternate peer or narrower build qualifies.
func loadNativeDAVStockPeer(t *testing.T) nativeDAVStockPeer {
	t.Helper()

	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Fatal("independent DAV application requires its authorized native Actions environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("independent DAV source differs from the actual Actions candidate")
	}
	rootRaw, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal("native repository root unavailable")
	}
	root := strings.TrimSpace(string(rootRaw))
	manifestPath := filepath.Join(root, ".private", "freightctl-rclone-v1.76.0-"+runtime.GOARCH, "manifest.json")
	manifestRaw, err := secure.ReadSecret(manifestPath, 1<<20)
	if err != nil {
		t.Fatal("exact private stock peer acquisition manifest required")
	}
	defer manifestRaw.Close()
	var manifest struct {
		Profile           string `json:"profile"`
		State             string `json:"state"`
		Candidate         string `json:"candidate"`
		Architecture      string `json:"architecture"`
		Module            string `json:"module"`
		Version           string `json:"version"`
		Revision          string `json:"upstream_revision"`
		ModuleSum         string `json:"module_sum"`
		GoModSum          string `json:"go_mod_sum"`
		GoVersion         string `json:"go_version"`
		Binary            string `json:"binary"`
		BinarySHA256      string `json:"binary_sha256"`
		ProtocolQualified bool   `json:"protocol_qualified"`
		Steps             []struct {
			Name string `json:"name"`
			Exit int    `json:"exit_code"`
		} `json:"steps"`
	}
	if json.Unmarshal(manifestRaw.Bytes, &manifest) != nil || manifest.Profile != "stock-rclone-webdav-v1" || manifest.State != "accepted-for-protocol-proof" || manifest.ProtocolQualified || manifest.Candidate != commit || manifest.Architecture != runtime.GOARCH || manifest.Module != "github.com/rclone/rclone" || manifest.Version != "v1.76.0" || manifest.Revision != "e982ff36668f5130d94b4f70409babb3d964df42" || manifest.ModuleSum != "h1:Gabl7KmhxyOXyMtFNA/s6wZ3LZ/2x0NP7xZLNEW3Guo=" || manifest.GoModSum != "h1:PoNZIA6Rv+01jY+WxLTz08i/QBEPz/6L5s1aD24Z5tc=" || manifest.GoVersion != "go1.27.3" {
		t.Fatal("stock application identity or evidence scope differs")
	}
	expectedSteps := []string{"native-toolchain", "verified-module", "stock-build", "binary-inventory", "complete-module-inventory", "verified-module-cache", "scanner-install", "scanner-converter-contract", "source-scan", "source-findings-gate", "binary-scan", "binary-findings-gate", "stock-version"}
	if len(manifest.Steps) != len(expectedSteps) {
		t.Fatal("stock peer security/acquisition steps incomplete")
	}
	for i, step := range manifest.Steps {
		if step.Name != expectedSteps[i] || step.Exit != 0 {
			t.Fatal("stock peer original security gate did not pass")
		}
	}
	expectedBinary := ".cache/freightctl-rclone-v1.76.0-" + runtime.GOARCH + "/bin/rclone"
	if filepath.ToSlash(manifest.Binary) != expectedBinary {
		t.Fatal("stock peer executable escaped its task-owned native cache")
	}
	binary := filepath.Join(root, filepath.FromSlash(expectedBinary))
	binaryInfo, err := os.Lstat(binary)
	if err != nil || !binaryInfo.Mode().IsRegular() || binaryInfo.Mode()&0111 == 0 {
		t.Fatal("stock peer executable missing or not a regular executable")
	}
	binaryFile, err := os.Open(binary)
	if err != nil {
		t.Fatal("scanned independent executable unavailable")
	}
	binaryDigest := secure.NewDigest()
	_, err = io.Copy(binaryDigest, binaryFile)
	binaryFile.Close()
	if err != nil || fmt.Sprintf("%x", binaryDigest.Sum(nil)) != manifest.BinarySHA256 {
		t.Fatal("actual independent executable differs from the scanned binary")
	}
	return nativeDAVStockPeer{Binary: binary, Commit: commit, ManifestSHA256: secure.Digest(manifestRaw.Bytes), BinarySHA256: manifest.BinarySHA256, PrivateDirectory: filepath.Dir(manifestPath)}
}
