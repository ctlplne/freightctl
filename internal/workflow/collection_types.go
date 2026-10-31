package workflow

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

const CollectionContract = "immutable-files-sha256-manifest-v1"

// CollectionSource belongs to the ordinary immutable workflow definition. The
// manifest is producer data, not a place to supply recipients or permissions.
type CollectionSource struct {
	Kind       string    `json:"kind"`
	Connection Reference `json:"connection"`
	Manifest   string    `json:"manifest"`
	Directory  string    `json:"target_directory"`
	Contract   string    `json:"completion_contract"`
	MaxFiles   int       `json:"max_files"`
	MaxFile    int64     `json:"max_file_bytes"`
	MaxTotal   int64     `json:"max_total_bytes"`
}
type CollectionFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}
type CollectionManifest struct {
	Schema int              `json:"schema_version"`
	Batch  string           `json:"batch_id"`
	Files  []CollectionFile `json:"files"`
}
type CollectionEffect struct {
	Kind       string           `json:"kind"`
	Connection ConnectionView   `json:"connection"`
	Source     CollectionSource `json:"source"`
}

func normalizeCollectionSource(s CollectionSource) error {
	dir, e := vpath.Canonical(s.Directory)
	if e != nil || dir != s.Directory || vpath.ControlPath(dir) || s.Kind != "sftp.collect" || (s.Contract != CollectionContract && s.Contract != ScheduledCollectionContract) || !store.ValidID(s.Connection.ID) || s.Connection.Version < 1 || s.Connection.Version > 2147483647 || !hashPattern.MatchString(s.Connection.Hash) || !collectionManifestPattern(s.Contract, s.Manifest) || s.MaxFiles < 1 || s.MaxFiles > 64 || s.MaxFile < 1 || s.MaxFile > 1<<30 || s.MaxTotal < 1 || s.MaxTotal > int64(s.MaxFiles)*s.MaxFile {
		return ErrInput
	}
	if _, e = vpath.Canonical(path.Join(s.Directory, strings.Repeat("x", 193))); e != nil {
		return ErrInput
	}
	return nil
}
func parseCollectionManifest(data []byte, source CollectionSource) (*CollectionManifest, string, error) {
	if normalizeCollectionSource(source) != nil {
		return nil, "", ErrInput
	}
	var m CollectionManifest
	if Decode(data, &m) != nil || m.Schema != 1 || !store.ValidID(m.Batch) || len(m.Files) < 1 || len(m.Files) > source.MaxFiles {
		return nil, "", ErrInput
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if !filenamePattern.MatchString(f.Name) || f.Name == source.Manifest || strings.HasSuffix(f.Name, ".ready.json") || seen[f.Name] || f.Size < 0 || f.Size > source.MaxFile || !hashPattern.MatchString(f.SHA256) || f.Size > source.MaxTotal-total {
			return nil, "", ErrInput
		}
		seen[f.Name] = true
		if _, e := vpath.Canonical(path.Join(source.Directory, f.SHA256+"-"+f.Name)); e != nil {
			return nil, "", ErrInput
		}
		total += f.Size
	}
	_, hash, e := digest(m)
	return &m, hash, e
}
func collectionConnection(ctx context.Context, t *store.Transaction, source *CollectionSource) (*ConnectionDefinition, *ConnectionView, error) {
	if source == nil || normalizeCollectionSource(*source) != nil {
		return nil, nil, ErrInput
	}
	for _, grant := range []string{"write", "list"} {
		if e := t.Require(grant); e != nil {
			return nil, nil, e
		}
	}
	if e := t.CheckAncestors(ctx, path.Join(source.Directory, "collection-target")); e != nil {
		return nil, nil, e
	}
	entry, e := t.Entry(ctx, source.Directory)
	if e != nil {
		return nil, nil, e
	}
	if entry.Kind != "dir" {
		return nil, nil, store.ErrState
	}
	if e = t.EntryMode(entry, 3); e != nil {
		return nil, nil, e
	}
	c, e := t.Configuration(ctx, true, source.Connection.ID, source.Connection.Version, false)
	if e != nil {
		return nil, nil, e
	}
	if c.Hash != source.Connection.Hash || c.State != "active" {
		return nil, nil, store.ErrState
	}
	var d ConnectionDefinition
	if json.Unmarshal(c.Definition, &d) != nil {
		return nil, nil, store.ErrState
	}
	_, hash, e := digest(d)
	if e != nil || hash != c.Hash || d.Schema != 1 {
		return nil, nil, store.ErrState
	}
	if e = secure.ValidateSSHDestination(d.Destination); e != nil {
		return nil, nil, e
	}
	v, e := viewConnection(c)
	return &d, &v, e
}
