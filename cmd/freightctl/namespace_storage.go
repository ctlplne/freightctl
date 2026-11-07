package main

func namespaceCommandNeedsStorage(operation string) bool {
	return operation == "publish" || operation == "copy" || operation == "copy_tree"
}
