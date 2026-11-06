package custody

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestArtifactIngressDescriptorRejectsInvalidIntegrityAndKeysBeforeResources(t *testing.T) {
	base := IngressDescriptorRequest{Size: 3, SHA256: strings.Repeat("a", 64), Key: "stable-upload-key"}
	for _, change := range []func(*IngressDescriptorRequest){func(r *IngressDescriptorRequest) { r.Size = -1 }, func(r *IngressDescriptorRequest) { r.Size = 4 }, func(r *IngressDescriptorRequest) { r.SHA256 = strings.Repeat("A", 64) }, func(r *IngressDescriptorRequest) { r.SHA256 = "unknown" }, func(r *IngressDescriptorRequest) { r.Key = "https://unapproved.invalid" }, func(r *IngressDescriptorRequest) { r.Key = "" }, func(r *IngressDescriptorRequest) { r.Key = strings.Repeat("x", 129) }} {
		r := base
		change(&r)
		if _, err := (&Service{MaxFile: 3}).PrepareArtifactIngress(context.Background(), store.Scope{}, r); !errors.Is(err, ErrInput) {
			t.Fatal("malformed descriptor reached a resource", err)
		}
	}
}
