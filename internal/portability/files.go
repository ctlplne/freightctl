// Package portability encodes and verifies versioned, inert exit artifacts.
package portability

import (
	"archive/tar"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

const (
	FilesProfile    = "freightctl-portable-files-v1"
	MaxFiles        = 64
	MaxPayloadBytes = 1 << 30
	maxManifest     = 16 << 10
	MaxArchiveBytes = MaxPayloadBytes + maxManifest + (MaxFiles+2)*1024 + 1024
)

var ErrBundle = errors.New("file bundle format, bounds or integrity check failed")

type File struct {
	ID     string `json:"id"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Profile       string `json:"profile"`
	SourceTenant  string `json:"source_tenant_id"`
	SourcePartner string `json:"source_partner_id"`
	Files         []File `json:"files"`
}

type Report struct {
	Manifest       Manifest `json:"manifest"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	ArchiveSHA256  string   `json:"archive_sha256"`
	PayloadBytes   int64    `json:"payload_bytes"`
}

func Selection(ids []string) ([]string, error) {
	if len(ids) < 1 || len(ids) > MaxFiles {
		return nil, ErrBundle
	}
	ordered := slices.Clone(ids)
	slices.Sort(ordered)
	for i, id := range ordered {
		if !store.ValidID(id) || (i > 0 && ordered[i-1] == id) {
			return nil, ErrBundle
		}
	}
	return ordered, nil
}

func manifestBytes(manifest Manifest) ([]byte, int64, error) {
	if manifest.SchemaVersion != 1 || manifest.Profile != FilesProfile || !store.ValidID(manifest.SourceTenant) ||
		!store.ValidID(manifest.SourcePartner) || len(manifest.Files) < 1 || len(manifest.Files) > MaxFiles {
		return nil, 0, ErrBundle
	}
	var total int64
	for i, file := range manifest.Files {
		digest, err := hex.DecodeString(file.SHA256)
		if !store.ValidID(file.ID) || (i > 0 && manifest.Files[i-1].ID >= file.ID) ||
			file.Size < 0 || file.Size > MaxPayloadBytes-total ||
			err != nil || len(digest) != 32 || hex.EncodeToString(digest) != file.SHA256 {
			return nil, 0, ErrBundle
		}
		total += file.Size
	}
	data, err := json.Marshal(manifest)
	return data, total, err
}

func fileName(file File) string { return "files/" + file.ID }

func writeHeader(archive *tar.Writer, name string, size int64) error {
	return archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0600, Size: size, Format: tar.FormatUSTAR})
}

func writeManifest(archive *tar.Writer, data []byte) error {
	if err := writeHeader(archive, "manifest.json", int64(len(data))); err != nil {
		return err
	}
	_, err := archive.Write(data)
	return err
}

func writeFile(archive *tar.Writer, file File, reader io.Reader) error {
	if err := writeHeader(archive, fileName(file), file.Size); err != nil {
		return err
	}
	hash := secure.NewDigest()
	n, err := io.Copy(io.MultiWriter(archive, hash), io.LimitReader(reader, file.Size))
	if err != nil {
		return err
	}
	var extra [1]byte
	trailing, end := reader.Read(extra[:])
	if n != file.Size || trailing != 0 || end != io.EOF || hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
		return ErrBundle
	}
	return nil
}

// WriteFiles writes a canonical USTAR stream. The caller owns private staging
// and decides when to publish the completed stream.
func WriteFiles(output io.Writer, manifest Manifest, open func(File) (io.ReadCloser, error)) (*Report, error) {
	data, total, err := manifestBytes(manifest)
	if err != nil {
		return nil, err
	}
	hash := secure.NewDigest()
	archive := tar.NewWriter(io.MultiWriter(output, hash))
	if err = writeManifest(archive, data); err != nil {
		return nil, err
	}
	for _, file := range manifest.Files {
		reader, err := open(file)
		if err != nil {
			return nil, err
		}
		if err = errors.Join(writeFile(archive, file, reader), reader.Close()); err != nil {
			return nil, err
		}
	}
	if err = archive.Close(); err != nil {
		return nil, err
	}
	return &Report{Manifest: manifest, ManifestSHA256: secure.Digest(data), ArchiveSHA256: hex.EncodeToString(hash.Sum(nil)), PayloadBytes: total}, nil
}

// VerifyFiles reads without extracting. It reconstructs the canonical archive
// into a second digest, so hidden headers, alternate metadata and padding
// cannot survive simply because the standard tar reader skips them.
func VerifyFiles(input io.Reader) (*Report, error) {
	raw := &io.LimitedReader{R: input, N: MaxArchiveBytes + 1}
	hash := secure.NewDigest()
	archive := tar.NewReader(io.TeeReader(raw, hash))
	header, err := archive.Next()
	if err != nil || header.Typeflag != tar.TypeReg || header.Name != "manifest.json" || header.Size < 1 || header.Size > maxManifest {
		return nil, ErrBundle
	}
	data, err := io.ReadAll(archive)
	if err != nil {
		return nil, ErrBundle
	}
	var manifest Manifest
	if json.Unmarshal(data, &manifest) != nil {
		return nil, ErrBundle
	}
	canonical, total, err := manifestBytes(manifest)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, ErrBundle
	}
	expected := secure.NewDigest()
	reencode := tar.NewWriter(expected)
	if writeManifest(reencode, data) != nil {
		return nil, ErrBundle
	}
	for _, file := range manifest.Files {
		header, err := archive.Next()
		if err != nil || header.Typeflag != tar.TypeReg || header.Name != fileName(file) || header.Size != file.Size ||
			writeFile(reencode, file, archive) != nil {
			return nil, ErrBundle
		}
	}
	var extra [1]byte
	_, end := archive.Next()
	n, trailing := raw.Read(extra[:])
	digest := hash.Sum(nil)
	if end != io.EOF || n != 0 || trailing != io.EOF || raw.N <= 0 || reencode.Close() != nil ||
		!bytes.Equal(digest, expected.Sum(nil)) {
		return nil, ErrBundle
	}
	return &Report{Manifest: manifest, ManifestSHA256: secure.Digest(data), ArchiveSHA256: hex.EncodeToString(digest), PayloadBytes: total}, nil
}
