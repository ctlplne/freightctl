package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

const LocalCollectionProfile = "freightctl-local-collection-source-v1"

// LocalCollectionSource is a reviewed reference to operator-owned private
// configuration. Neither a workflow nor a browser can introduce a host path.
type LocalCollectionSource struct {
	Schema          int    `json:"schema_version"`
	Reference       string `json:"root_reference"`
	SHA256          string `json:"configuration_sha256"`
	RootFingerprint string `json:"root_fingerprint"`
}

func (d *LocalCollectionSource) Valid() bool {
	return d != nil && d.Schema == 1 && len(d.Reference) <= 4096 && filepath.IsAbs(d.Reference) && filepath.Clean(d.Reference) == d.Reference && !strings.ContainsAny(d.Reference, "\x00\r\n") && localCollectionDigest(d.SHA256) && localCollectionDigest(d.RootFingerprint)
}

func localCollectionDirectory(raw []byte, expected string) (string, error) {
	if len(raw) == 0 || len(raw) > 32<<10 || !utf8.Valid(raw) {
		return "", ErrLocalSource
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return "", ErrLocalSource
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"schema_version": true, "profile": true, "directory": true, "root_fingerprint": true}
	directory := ""
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !allowed[key] {
			return "", ErrLocalSource
		}
		seen[key] = true
		value, err := d.Token()
		if err != nil {
			return "", ErrLocalSource
		}
		switch key {
		case "schema_version":
			if number, ok := value.(json.Number); !ok || number.String() != "1" {
				return "", ErrLocalSource
			}
		case "profile":
			if value != LocalCollectionProfile {
				return "", ErrLocalSource
			}
		case "root_fingerprint":
			if value != expected || !localCollectionDigest(expected) {
				return "", ErrLocalSource
			}
		case "directory":
			var ok bool
			directory, ok = value.(string)
			if !ok || len(directory) > 4096 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || strings.ContainsAny(directory, "\x00\r\n") {
				return "", ErrLocalSource
			}
		default:
			return "", ErrLocalSource
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 4 {
		return "", ErrLocalSource
	}
	if _, err = d.Token(); err != io.EOF {
		return "", ErrLocalSource
	}
	return directory, nil
}

func OpenConfiguredLocalCollectionPeer(ctx context.Context, definition *LocalCollectionSource, check func() error) (*LocalCollectionPeer, error) {
	if !definition.Valid() || check == nil {
		return nil, ErrLocalSource
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	profile, err := secure.ReadSecret(definition.Reference, 32<<10)
	if err != nil {
		return nil, ErrLocalSource
	}
	defer profile.Close()
	if secure.Digest(profile.Bytes) != definition.SHA256 {
		return nil, ErrLocalSource
	}
	directory, err := localCollectionDirectory(profile.Bytes, definition.RootFingerprint)
	if err != nil {
		return nil, err
	}
	return OpenLocalCollectionPeer(ctx, directory, definition.RootFingerprint, check)
}
