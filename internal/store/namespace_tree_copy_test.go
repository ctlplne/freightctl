package store

import (
	"errors"
	"testing"
)

func TestTreeCopyRequiresReadListAndWriteWithoutImplicitManagement(t *testing.T) {
	revision := int64(1)
	for _, operation := range []string{"copy_tree", "copy_dir"} {
		base := PathCommand{Operation: operation, Path: "/source", Target: "/target", ExpectedEntryID: "10000000-1111-4111-8111-111111111111", ExpectedRevision: &revision}
		if err := validateTreeMove(base); err != nil {
			t.Fatal("valid copy shape refused", err)
		}
		for _, test := range []struct {
			name        string
			permissions []string
			change      func(*PathCommand)
			want        error
		}{
			{"no write", []string{"read", "list", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
			{"no read", []string{"list", "write", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
			{"no list", []string{"read", "write", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
			{"no identity", []string{"read", "list", "write"}, func(c *PathCommand) { c.ExpectedEntryID = "" }, ErrState},
			{"overwrite", []string{"read", "list", "write"}, func(c *PathCommand) { c.Replace = true }, ErrState},
			{"target revision", []string{"read", "list", "write"}, func(c *PathCommand) { c.TargetRevision = &revision }, ErrState},
			{"self", []string{"read", "list", "write"}, func(c *PathCommand) { c.Target = c.Path }, ErrForbidden},
			{"descendant", []string{"read", "list", "write"}, func(c *PathCommand) { c.Target = c.Path + "/nested" }, ErrForbidden},
		} {
			t.Run(operation+"/"+test.name, func(t *testing.T) {
				c := base
				test.change(&c)
				tx := &Transaction{Root: "/", Permissions: test.permissions}
				if _, err := tx.PrepareTreeCopy(t.Context(), c); !errors.Is(err, test.want) {
					t.Fatal("copy preflight reached database or changed authority", err)
				}
				if _, err := tx.ApplyPathCommand(t.Context(), "tree-copy-original", c, 1000); !errors.Is(err, test.want) {
					t.Fatal("copy command bypassed preflight guard", err)
				}
			})
		}
	}
}
