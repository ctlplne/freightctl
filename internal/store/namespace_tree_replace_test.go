package store

import (
	"errors"
	"testing"
)

func TestTreeReplacementRequiresBothIdentitiesAndDisjointTrees(t *testing.T) {
	revision := int64(1)
	base := PathCommand{Operation: "move_tree", Path: "/source", Target: "/target", ExpectedEntryID: "10000000-1111-4111-8111-111111111111", ExpectedRevision: &revision, Replace: true, TargetEntryID: "20000000-1111-4111-8111-111111111111", TargetRevision: &revision}
	if err := validateTreeMove(base); err != nil {
		t.Fatal("two exact tree identities refused", err)
	}
	for _, test := range []struct {
		name   string
		change func(*PathCommand)
		want   error
	}{
		{"no destination ID", func(c *PathCommand) { c.TargetEntryID = "" }, ErrState},
		{"no destination revision", func(c *PathCommand) { c.TargetRevision = nil }, ErrState},
		{"destination without overwrite", func(c *PathCommand) { c.Replace = false }, ErrState},
		{"ancestor destination", func(c *PathCommand) { c.Path = "/target/source" }, ErrForbidden},
		{"descendant destination", func(c *PathCommand) { c.Target = "/source/target" }, ErrForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := base
			test.change(&command)
			if err := validateTreeMove(command); !errors.Is(err, test.want) {
				t.Fatal("ambiguous or overlapping replacement admitted", err)
			}
		})
	}
	base.Operation = "copy_tree"
	transaction := &Transaction{Root: "/", Permissions: []string{"read", "list", "write"}}
	if _, err := transaction.PrepareTreeCopy(t.Context(), base); !errors.Is(err, ErrForbidden) {
		t.Fatal("copy overwrite preflight lacked management", err)
	}
	if _, err := transaction.ApplyPathCommand(t.Context(), "replace-original", base, 1000); !errors.Is(err, ErrForbidden) {
		t.Fatal("copy overwrite command bypassed management", err)
	}
	if _, err := transaction.ReadPathCommandReceipt(t.Context(), "replace-original", base); !errors.Is(err, ErrForbidden) {
		t.Fatal("historical overwrite receipt bypassed original management", err)
	}
	if err := transaction.treeCopyCapacity(t.Context(), 1000, 600, 401); !errors.Is(err, ErrLimit) {
		t.Fatal("combined source/destination operation widened existing1000-entry processing bound", err)
	}
	base.Operation = "mkdir"
	base.ExpectedEntryID = ""
	base.ExpectedRevision = nil
	base.Replace = false
	base.TargetRevision = nil
	transaction.Permissions = []string{"read", "list", "write", "manage_paths"}
	if _, err := transaction.ApplyPathCommand(t.Context(), "target-identity-unexpected", base, 1000); !errors.Is(err, ErrState) {
		t.Fatal("unrelated namespace operation ignored destination identity", err)
	}
}
