package store

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNamespaceReceiptMeaningKeepsOriginalCanonicalHashAndAuthorityFence(t *testing.T) {
	transaction := &Transaction{Root: "/", AuthorityRevision: 7}
	command, actual, hash, err := transaction.pathCommandMeaning(PathCommand{Operation: "mkdir", Path: "/safe"})
	if err != nil || actual != "/safe" || command.Path != "/safe" || hash != "b33bdcb548951183fb336740d085034be58a5aba2470b168a25f66d29cb2dad7" {
		t.Fatal("old canonical command meaning changed", err, hash)
	}
	timestamp := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.FixedZone("local", -4*60*60))
	zero := int64(0)
	mode := uint32(0)
	transaction = &Transaction{Root: "/mount", AuthorityRevision: 3}
	input := PathCommand{Operation: "setstat", Path: "/cafe\u0301", ExpectedRevision: &zero, Mode: &mode, Modified: &timestamp}
	normalized, actual, hash, err := transaction.pathCommandMeaning(input)
	if err != nil || actual != "/mount/café" || normalized.Path != "/café" || normalized.Modified == nil || normalized.Modified.Nanosecond() != 123456000 || normalized.Modified.Location() != time.UTC || hash != "71e0dce457580236105cf196029a89f303881699f9e9af127513e660a19cf5c7" {
		t.Fatal("Unicode,explicit zero or timestamp changed existing receipt meaning", err, hash)
	}
	for _, tx := range []*Transaction{{Root: "/other", AuthorityRevision: 3}, {Root: "/mount", AuthorityRevision: 4}} {
		_, _, other, err := tx.pathCommandMeaning(input)
		if err != nil || other == hash {
			t.Fatal("receipt meaning lost mount/authority fence", err)
		}
	}
	input.Mode = nil
	if _, _, other, err := transaction.pathCommandMeaning(input); err != nil || other == hash {
		t.Fatal("explicit zero was erased from original command meaning", err)
	}
}

func TestNamespaceReceiptCannotReachRowsWithoutOriginalCommandAuthority(t *testing.T) {
	command := PathCommand{Operation: "remove_tree", Path: "/source"}
	for _, test := range []struct {
		permissions []string
		key         string
		operation   string
		want        error
	}{
		{[]string{"read", "list", "manage_paths"}, "", "remove_tree", ErrState},
		{[]string{"read", "list"}, "original", "remove_tree", ErrForbidden},
		{[]string{"read", "manage_paths"}, "original", "remove_tree", ErrForbidden},
		{[]string{"list", "manage_paths"}, "original", "remove_tree", ErrForbidden},
		{[]string{"read", "list", "manage_paths"}, "original", "copy_tree", ErrForbidden},
		{[]string{"read", "list", "write"}, "original", "properties", ErrForbidden},
		{[]string{"read", "list", "write", "manage_paths"}, "original", "unknown", ErrState},
	} {
		transaction := &Transaction{Root: "/", Permissions: test.permissions}
		command.Operation = test.operation
		if _, err := transaction.ReadPathCommandReceipt(t.Context(), test.key, command); !errors.Is(err, test.want) {
			t.Fatal("read-only receipt reached storage without authority", err)
		}
	}
	for _, key := range []string{"", "space key", "../path", strings.Repeat("x", 129)} {
		if ValidNamespaceRequestKey(key) {
			t.Fatal("ambiguous original receipt key admitted")
		}
	}
}
