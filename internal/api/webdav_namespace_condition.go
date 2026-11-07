package api

import (
	"strconv"
	"strings"

	"github.com/ctlplne/freightctl/internal/store"
)

func davNamespaceCondition(value string) (string, int64, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || !store.ValidID(parts[0]) {
		return "", 0, false
	}
	revision, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || revision < 1 || strconv.FormatInt(revision, 10) != parts[1] {
		return "", 0, false
	}
	return parts[0], revision, true
}
