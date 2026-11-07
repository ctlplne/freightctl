package store

import (
	"errors"
	"testing"

	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/vpath"
)

func TestTreeRemovalRequiresExactIdentityAndIndependentManagementAuthority(t *testing.T) {
	revision := int64(1)
	base := PathCommand{Operation: "remove_tree", Path: "/source", ExpectedEntryID: "10000000-1111-4111-8111-111111111111", ExpectedRevision: &revision}
	if err := validateTreeRemoval(base); err != nil {
		t.Fatal("valid whole-tree removal rejected", err)
	}
	for _, test := range []struct {
		name        string
		permissions []string
		change      func(*PathCommand)
		want        error
	}{
		{"no management", []string{"read", "list", "write"}, func(*PathCommand) {}, ErrForbidden},
		{"no read", []string{"list", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
		{"no list", []string{"read", "manage_paths"}, func(*PathCommand) {}, ErrForbidden},
		{"root", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Path = "/" }, ErrForbidden},
		{"control path", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Path = "/.freightctl" }, ErrForbidden},
		{"noncanonical", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Path = "/e\u0301" }, vpath.ErrPath},
		{"missing identity", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.ExpectedEntryID = "" }, ErrState},
		{"missing revision", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.ExpectedRevision = nil }, ErrState},
		{"target", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Target = "/another" }, ErrState},
		{"file identity", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.FileID = c.ExpectedEntryID }, ErrState},
		{"replacement", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { c.Replace = true }, ErrState},
		{"mode", []string{"read", "list", "manage_paths"}, func(c *PathCommand) { m := uint32(0); c.Mode = &m }, ErrState},
		{"property changes", []string{"read", "list", "manage_paths"}, func(c *PathCommand) {
			c.PropertyChanges = []namespaceprops.Change{{Operation: "remove", Property: `<data xmlns="urn:example"/>`}}
		}, ErrState},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := base
			test.change(&command)
			transaction := &Transaction{Root: "/", Permissions: test.permissions}
			_, err := transaction.ApplyPathCommand(t.Context(), "tree-remove-original", command, 1000)
			if !errors.Is(err, test.want) {
				t.Fatal("tree removal reached storage or admitted ambiguous authority", err)
			}
		})
	}
}
