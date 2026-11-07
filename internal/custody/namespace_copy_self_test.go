package custody

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestNamespaceCopyRefusesItsOwnSourceBeforeDatabaseAccess(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "replace"}[replace], func(t *testing.T) {
			defer func() {
				if recover() != nil {
					t.Fatal("self-copy reached database access instead of refusing the invalid operation")
				}
			}()
			revision := int64(1)
			_, err := (&Service{}).PathCommand(context.Background(), store.Scope{}, "self-copy", store.PathCommand{Operation: "copy", Path: "/same.dat", Target: "/same.dat", FileID: "10000000-1111-4111-8111-111111111111", ExpectedRevision: &revision, Replace: replace})
			if !errors.Is(err, store.ErrForbidden) {
				t.Fatal("self-copy was not refused as a same-resource operation", err)
			}
		})
	}
}
