package workflow

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestPortableWorkflowListsDistinctExactDependencyVersions(t *testing.T) {
	a := Reference{ID: "10000000-0000-4000-8000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}
	b := Reference{ID: a.ID, Version: 2, Hash: strings.Repeat("b", 64)}
	key := store.PGPReference{ID: "20000000-0000-4000-8000-000000000002", Version: 4, Hash: strings.Repeat("c", 64)}
	d := Definition{Source: &CollectionSource{Connection: a},
		Steps: []Step{{Connection: a}, {Connection: b, Encryption: &store.EncryptionPolicy{Key: key}}}}
	got := portableDependencies(d)
	want := []PortableWorkflowDependency{
		{Kind: "connection", ID: a.ID, Version: a.Version, Hash: a.Hash},
		{Kind: "connection", ID: b.ID, Version: b.Version, Hash: b.Hash},
		{Kind: "public_encryption_key", ID: key.ID, Version: key.Version, Hash: key.Hash},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dependency identity or order changed: %#v", got)
	}
}
