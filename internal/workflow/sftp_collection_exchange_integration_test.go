//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

// The producer and receiver use separate stock daemons, directories and keys.
// The collector credential can read the ready manifest and payload on the source.
func TestStockSFTPCollectionToAgentAndSeparatelyApprovedStockSFTP(t *testing.T) {
	testStockSFTPCollectionToAgent(t, false)
}

func TestStockSFTPCollectionToAgentOverMCPAndSeparatelyApprovedStockSFTP(t *testing.T) {
	testStockSFTPCollectionToAgent(t, true)
}

func testStockSFTPCollectionToAgent(t *testing.T, useMCP bool) {
	t.Helper()
	binary := routingKeyCLI(t)
	f := setup(t)
	producer := newStockSFTPPeer(t, f, true)
	source, selection := prepareCollectionTest(t, f, producer.connection, false, false)
	body := []byte("abc")
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(),
		Files: []CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}},
	}
	raw, _, err := digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{source.Manifest: raw, "one.csv": body}
	for name, data := range files {
		if err = os.WriteFile(filepath.Join(producer.directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	proveCollectionAgentOnward(t, f, selection, binary, body, "", manifest, func() int64 {
		return int64(producer.sessions(t))
	}, useMCP)

	// Check the peer's own read-only policy with the actual collection key.
	batch := filepath.Join(t.TempDir(), "write.batch")
	replace := filepath.Join(producer.directory, "unexpected.csv")
	line := "put " + strconv.Quote(filepath.Join(producer.directory, "one.csv")) + " " + strconv.Quote(replace) + "\n"
	if err = os.WriteFile(batch, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(f.ctx, "sftp", producer.sftpArgs(batch)...).CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("Permission denied")) || producer.sessions(t) != 2 {
		t.Fatalf("stock source did not refuse the authenticated write; output_sha256=%s", secure.Digest(output))
	}
	entries, err := os.ReadDir(producer.directory)
	if err != nil || len(entries) != len(files) {
		t.Fatal("source directory entry count changed", err)
	}
	for name, expected := range files {
		actual, err := os.ReadFile(filepath.Join(producer.directory, name))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("source file bytes changed", err)
		}
	}
}
