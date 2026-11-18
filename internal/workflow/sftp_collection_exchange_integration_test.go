//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
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

func TestStockSFTPCollectionKilledAfterSealRecoversExactExchangeSource(t *testing.T) {
	binary := routingKeyCLI(t)
	f := setup(t)
	producer := newStockSFTPPeer(t, f, true)
	source, selection := prepareCollectionTest(t, f, producer.connection, false, false)
	body := []byte("exact stock SFTP source sealed before acceptance\n")
	manifest, files := publishStockSFTPCollection(t, producer.directory, source.Manifest, body)
	contacts := func() int64 { return int64(producer.sessions(t)) }
	captured := proveCollectionAfterSealDeath(t, f, binary, selection, body, manifest, contacts, func() {
		for name, expected := range files {
			filename := filepath.Join(producer.directory, name)
			data, err := os.ReadFile(filename)
			if err != nil || !bytes.Equal(data, expected) {
				t.Fatal("original read changed stock producer files", err)
			}
			if err = os.Remove(filename); err != nil {
				t.Fatal("withdraw the exact fixture source before replacement", err)
			}
		}
	})
	input, job := captured.Inputs[0], captured.Job
	argv := []string{"workflow-collection-exchange-source", "--dsn-file", f.runtimePath,
		"--token-file", f.tokenPath, "--tenant", f.scope.Tenant, "--partner", f.scope.Partner,
		"--storage", f.storagePath, "--collection-id", job.ID, "--collection-input-id", input.ID}
	wire, err := exec.CommandContext(f.ctx, binary, argv...).Output()
	var review CollectedExchangeSource
	if err != nil || json.Unmarshal(wire, &review) != nil || review.Profile != CollectedExchangeSourceProfile ||
		review.State != "source-review-only" || review.StorageVerification != "not-checked" ||
		review.Origin.CollectionID != job.ID || review.Origin.FirstCollectionID != job.ID || review.Origin.DefinitionHash != job.Hash ||
		review.Origin.Workflow != selection.Workflow || review.Origin.ManifestHash != *job.ManifestHash || review.Origin.ProducerBatch != manifest.Batch ||
		review.Origin.InputID != input.ID || review.Origin.InputIdentity != input.Identity ||
		review.Artifact.ID != input.ObjectID || review.Artifact.Size != int64(len(body)) || review.Artifact.SHA256 != secure.Digest(body) || contacts() != 1 {
		t.Fatalf("stock SFTP recovery changed the exact exchange source; output_sha256=%s; error=%v", secure.Digest(wire), err)
	}
}

func testStockSFTPCollectionToAgent(t *testing.T, useMCP bool) {
	t.Helper()
	binary := routingKeyCLI(t)
	f := setup(t)
	producer := newStockSFTPPeer(t, f, true)
	source, selection := prepareCollectionTest(t, f, producer.connection, false, false)
	body := []byte("abc")
	manifest, files := publishStockSFTPCollection(t, producer.directory, source.Manifest, body)
	proveCollectionAgentOnward(t, f, selection, binary, body, "", manifest, func() int64 {
		return int64(producer.sessions(t))
	}, useMCP)

	// Check the peer's own read-only policy with the actual collection key.
	batch := filepath.Join(t.TempDir(), "write.batch")
	replace := filepath.Join(producer.directory, "unexpected.csv")
	line := "put " + strconv.Quote(filepath.Join(producer.directory, "one.csv")) + " " + strconv.Quote(replace) + "\n"
	if err := os.WriteFile(batch, []byte(line), 0600); err != nil {
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

func publishStockSFTPCollection(t *testing.T, directory, manifestName string, body []byte) (*CollectionManifest, map[string][]byte) {
	t.Helper()
	manifest := &CollectionManifest{Schema: 1, Batch: secure.NewID(),
		Files: []CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}},
	}
	raw, _, err := digest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{manifestName: raw, "one.csv": body}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return manifest, files
}
