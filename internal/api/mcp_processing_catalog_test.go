package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestMCPProcessingCatalogOmitsNamesAndCannotPromiseExecution(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	hash := strings.Repeat("a", 64)
	page := &workflow.ProcessingCatalog{Profile: "processing-workflow-catalog-v1", Authority: 7, RootDigest: hash, Workflows: []workflow.ProcessingCatalogEntry{{Reference: workflow.Reference{ID: id, Version: 1, Hash: hash}, Name: "PRIVATE_WORKFLOW_NAME", State: "approved", Revision: 2, Kind: "records.project", SourcePolicyHash: hash, OutputKind: "json_records", ColumnCount: 2, OutputPolicy: workflow.Reference{ID: id, Version: 2, Hash: hash}, ApprovalCurrent: false, OutputPolicyCurrent: true}}}
	facts, err := mcpProcessingCatalog(page)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(facts)
	if strings.Contains(string(raw), "PRIVATE_") || facts["execution_readiness"] != "not-checked" || facts["effects"] != "none" {
		t.Fatal("catalog exposed names or inferred authority")
	}
	page.Workflows[0].State = "draft"
	page.Workflows[0].ApprovalCurrent = true
	if _, err = mcpProcessingCatalog(page); err == nil {
		t.Fatal("draft claimed current approval")
	}
}
func TestMCPProcessingCatalogInputRefusalIsIndependentOfReceiveAdapter(t *testing.T) {
	s := &Server{Service: &custody.Service{}}
	_, err := s.callMCPTool(context.Background(), store.Scope{}, "freightctl.list_processing_workflows", mcpToolArguments{Limit: 101})
	if !errors.Is(err, workflow.ErrInput) {
		t.Fatal("processing catalog depended on optional receive adapter", err)
	}
}
