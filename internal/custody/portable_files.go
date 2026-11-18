package custody

import (
	"context"
	"io"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/portability"
	"github.com/ctlplne/freightctl/internal/store"
)

// PreparePortableFiles writes only to private staging. Its event records
// preparation of exact bytes and does not claim publication on the caller's disk.
func (s *Service) PreparePortableFiles(ctx context.Context, scope store.Scope, ids []string, output io.Writer) (*portability.Report, error) {
	ordered, err := portability.Selection(ids)
	if err != nil {
		return nil, err
	}
	tx, err := s.DB.Begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	defer tx.Tx.Rollback(ctx)
	if err = tx.Require("read"); err != nil {
		return nil, err
	}
	manifest := portability.Manifest{
		SchemaVersion: 1, Profile: portability.FilesProfile,
		SourceTenant: scope.Tenant, SourcePartner: scope.Partner,
		Files: make([]portability.File, 0, len(ordered)),
	}
	for _, id := range ordered {
		if err = tx.FileAccessible(ctx, id); err != nil {
			return nil, err
		}
		file, err := tx.File(ctx, id)
		if err != nil {
			return nil, err
		}
		manifest.Files = append(manifest.Files, portability.File{ID: file.ID, Size: file.Size, SHA256: file.SHA256})
	}
	if err = s.Disk.CheckIdentity(); err != nil {
		return nil, err
	}
	report, err := portability.WriteFiles(output, manifest, func(file portability.File) (io.ReadCloser, error) {
		handle, err := s.Disk.VerifiedContext(ctx, Name(scope.Tenant, scope.Partner, file.ID), file.Size, file.SHA256)
		if err != nil {
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{contextReader{ctx, handle}, handle}, nil
	})
	if err != nil {
		return nil, err
	}
	if err = tx.Reauthorize(ctx); err != nil {
		return nil, err
	}
	if err = tx.Require("read"); err != nil {
		return nil, err
	}
	for _, id := range ordered {
		if err = tx.FileAccessible(ctx, id); err != nil {
			return nil, err
		}
	}
	_, err = tx.Append(ctx, "PortableFilesExportPrepared", secure.NewID(), struct {
		Files          []portability.File `json:"files"`
		ManifestSHA256 string             `json:"manifest_sha256"`
		ArchiveSHA256  string             `json:"archive_sha256"`
	}{Files: manifest.Files, ManifestSHA256: report.ManifestSHA256, ArchiveSHA256: report.ArchiveSHA256})
	if err != nil {
		return nil, err
	}
	if err = tx.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return report, nil
}
