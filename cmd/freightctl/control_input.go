package main

import (
	"io"

	"github.com/ctlplne/freightctl/internal/workflow"
)

// Namespace and upload controls share the API's typed object decoder. Read one
// byte beyond the existing limit so a truncated stream cannot fabricate EOF.
func decodeCLIControl(input io.Reader, target any, maximum int64) error {
	if maximum < 1 || maximum > 32<<10 {
		return workflow.ErrInput
	}
	data, err := io.ReadAll(io.LimitReader(input, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return workflow.ErrInput
	}
	return workflow.Decode(data, target)
}
