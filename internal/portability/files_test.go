package portability

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestPortableFilesArchiveCanonicalAndEveryMemberVerified(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: 1, Profile: FilesProfile,
		SourceTenant: "10000000-0000-4000-8000-000000000001", SourcePartner: "10000000-0000-4000-8000-000000000002",
		Files: []File{
			{ID: "20000000-0000-4000-8000-000000000001", Size: 6, SHA256: secure.Digest([]byte("batch1"))},
			{ID: "20000000-0000-4000-8000-000000000002", Size: 0, SHA256: secure.Digest(nil)},
		},
	}
	open := func(file File) (io.ReadCloser, error) {
		payload := ""
		if file.Size != 0 {
			payload = "batch1"
		}
		return io.NopCloser(bytes.NewBufferString(payload)), nil
	}
	var output bytes.Buffer
	exported, err := WriteFiles(&output, manifest, open)
	if err != nil {
		t.Fatal(err)
	}
	raw := output.Bytes()
	verified, err := VerifyFiles(bytes.NewReader(raw))
	if err != nil || !reflect.DeepEqual(verified, exported) || verified.ArchiveSHA256 != secure.Digest(raw) || verified.PayloadBytes != 6 {
		t.Fatalf("portable bytes did not round trip: %v", err)
	}
	changed := bytes.Clone(raw)
	changed[bytes.Index(changed, []byte("batch1"))] = 'B'
	// The tar header and payload are valid independently in these variants.
	// The profile still rejects an alternate mode and a repeated manifest field.
	build := func(mode int64, data []byte, name string) []byte {
		t.Helper()
		var buffer bytes.Buffer
		archive := tar.NewWriter(&buffer)
		for _, entry := range []struct {
			name string
			body []byte
		}{
			{"manifest.json", data}, {name, []byte("batch1")}, {fileName(manifest.Files[1]), nil},
		} {
			if err := archive.WriteHeader(&tar.Header{Name: entry.name, Mode: mode, Size: int64(len(entry.body))}); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	jsonBytes, _ := json.Marshal(manifest)
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"payload", changed},
		{"trailing-data", append(bytes.Clone(raw), 1)},
		{"missing-terminal-record", raw[:len(raw)-512]},
		{"alternate-mode", build(0644, jsonBytes, fileName(manifest.Files[0]))},
		{"alias-member", build(0600, jsonBytes, "files/../"+manifest.Files[0].ID)},
		{"duplicate-manifest-key", build(0600, bytes.Replace(jsonBytes, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), fileName(manifest.Files[0]))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if report, err := VerifyFiles(bytes.NewReader(test.raw)); !errors.Is(err, ErrBundle) || report != nil {
				t.Fatalf("invalid archive obtained verification: %v", err)
			}
		})
	}
}
