package main

import "testing"

func TestNamespaceStorageDecisionIncludesEveryBytePublishingCommand(t *testing.T) {
	for _, operation := range []string{"publish", "copy", "copy_tree"} {
		if !namespaceCommandNeedsStorage(operation) {
			t.Errorf("byte-publishing command %s cannot verify custody without opening storage", operation)
		}
	}
	for _, operation := range []string{"copy_dir", "move_tree", "remove_tree", "properties", "rename", "setstat", "mkdir", "remove", "rmdir"} {
		if namespaceCommandNeedsStorage(operation) {
			t.Errorf("metadata-only command %s unnecessarily opens custody storage", operation)
		}
	}
}
