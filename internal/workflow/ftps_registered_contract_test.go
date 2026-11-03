package workflow

import (
	"strings"
	"testing"
)

// F073 freezes the missing typed operation before implementation. No peer,
// database, credentials, model or scanner is opened by normalization.
func TestRegisteredFTPSWorkflowUsesVersionedConnectionReference(t *testing.T) {
	d := Definition{Schema: 1, Name: "Explicitly approved FTPS settlement", Steps: []Step{{ID: "send", Kind: "ftps.deliver", Connection: Reference{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: strings.Repeat("a", 64)}, Filename: "settlement.csv"}}}
	normalized, err := Normalize(d)
	if err != nil {
		t.Fatalf("registered FTPS delivery is missing from the typed workflow: %v", err)
	}
	if len(normalized.Steps) != 1 || normalized.Steps[0].Kind != "ftps.deliver" || normalized.Steps[0].Connection != d.Steps[0].Connection {
		t.Fatal("normalization changed protocol or approved connection revision")
	}
}
