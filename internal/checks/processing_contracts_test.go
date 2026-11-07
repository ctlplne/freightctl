package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProcessingContractsExposeOwnedSchemaWithoutPrivateBindingsOrPayload(t *testing.T) {
	base, row, _, now := projectionReviewFixture(t)
	base.Plan.Root = "/PRIVATE_ROOT"
	base.Plan.Source.Check.Binding.Root = base.Plan.Root
	row.Binding, _, _ = canonical(base.Plan.Source.Check.Binding)
	base.Plan.Reason = "PRIVATE_REASON"
	got, err := processingContracts(base, row, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source.ID != base.Plan.Source.File.ID || got.SourcePolicy.Reference.Hash != row.PolicyHash || got.OutputPolicy.Reference != base.Plan.Policy || got.Authority != base.Plan.Authority {
		t.Fatal("schema metadata lost exact source/policy/authority")
	}
	wire, _ := json.Marshal(got)
	for _, hidden := range []string{"PRIVATE_ROOT", "PRIVATE_REASON", "storage_id", "parent_id", "staging_slots", projectionInput} {
		if strings.Contains(string(wire), hidden) {
			t.Fatal("private bindings or bytes entered metadata description")
		}
	}
	base.PreviousPolicy.Definition.Columns[0].Name = "changed-after-response"
	if got.SourcePolicy.Definition.Columns[0].Name == "changed-after-response" {
		t.Fatal("caller changed returned reviewed schema")
	}
	row.ReportHash = strings.Repeat("f", 64)
	if _, err = processingContracts(base, row, now); err == nil {
		t.Fatal("unverified source described as eligible processing")
	}
}
