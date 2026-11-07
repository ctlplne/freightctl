package store

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/vpath"
)

func TestTreeMoveRefusesAmbiguousAuthorityAndTargetsBeforeDatabaseAccess(t *testing.T) {
	revision := int64(1)
	base := PathCommand{Operation: "move_tree", Path: "/source", Target: "/target", ExpectedEntryID: "10000000-1111-4111-8111-111111111111", ExpectedRevision: &revision}
	for _, test := range []struct {
		name        string
		permissions []string
		change      func(*PathCommand)
		want        error
	}{
		{"self", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Target = c.Path }, ErrForbidden},
		{"descendant", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Target = c.Path + "/nested" }, ErrForbidden},
		{"no management", []string{"read", "list"}, func(*PathCommand) {}, ErrForbidden},
		{"no read", []string{"list", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
		{"no list", []string{"read", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
		{"overwrite", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Replace = true }, ErrState},
		{"missing identity", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.ExpectedEntryID = "" }, ErrState},
		{"normalization alias", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Target = "/e\u0301" }, vpath.ErrPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := base
			test.change(&command)
			transaction := &Transaction{Root: "/", Permissions: test.permissions}
			_, err := transaction.ApplyPathCommand(t.Context(), "tree-move-original", command, 10000)
			if !errors.Is(err, test.want) {
				t.Fatal("tree command reached database or admitted ambiguous authority/target", err)
			}
		})
	}
}
