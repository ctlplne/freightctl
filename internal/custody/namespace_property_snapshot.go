package custody

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type NamespacePropertySnapshot struct {
	Profile     string            `json:"profile"`
	Observation string            `json:"observation"`
	Entry       store.PathEntry   `json:"entry"`
	Properties  map[string]string `json:"properties"`
}

// ReadNamespacePropertySnapshot is an explicit content read. Ordinary stat and
// list keep their metadata-only contracts;this single-resource snapshot uses
// DAV's same read/list,mount/mode,current-intake and shared-lock checks.
func (s *Service) ReadNamespacePropertySnapshot(ctx context.Context, scope store.Scope, virtual string) (*NamespacePropertySnapshot, error) {
	canonical, err := vpath.Canonical(virtual)
	if err != nil || canonical != virtual || vpath.ControlPath(canonical) {
		return nil, vpath.ErrPath
	}
	properties, err := s.ReadNamespaceProperties(ctx, scope, canonical, false)
	if err != nil {
		return nil, err
	}
	if len(properties) != 1 {
		return nil, store.ErrState
	}
	return &NamespacePropertySnapshot{Profile: "namespace-properties-v1", Observation: "authorized-snapshot-at-read", Entry: properties[0].Entry, Properties: properties[0].Properties}, nil
}
