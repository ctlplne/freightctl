package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/recordplan"
	"github.com/ctlplne/freightctl/internal/store"
)

func processingWorkflow(t testing.TB) Definition {
	t.Helper()
	h := strings.Repeat("a", 64)
	return Definition{Schema: 3, Name: "Receive settlement and create held validated output", Processing: &ProcessingTask{ID: "project", Kind: "records.project", OutputPolicy: Reference{ID: "11111111-1111-4111-8111-111111111111", Version: 2, Hash: strings.Repeat("b", 64)}, Reason: "Map reviewed settlement records", Definition: recordplan.Projection{Schema: 1, Kind: "record_projection", Engine: "freightctl-record-projection-v1", SourcePolicyHash: h, OutputKind: "json_records", Columns: []recordplan.Column{{Source: "account", Target: "account"}}, MaxBytes: 8192, MaxRows: 100, MaxRecordBytes: 1024, TimeoutSeconds: 2}}}
}

func TestProcessingWorkflowDraftRequiresManagementBeforeAnySQL(t *testing.T) {
	tx := &store.Transaction{Root: "/processor", Permissions: []string{"read", "write", "check_run", "workflow_execute"}}
	_, err := StageDraft(context.Background(), tx, DraftRequest{Definition: processingWorkflow(t)})
	if !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("execution rights acquired workflow management: %v", err)
	}
}

func TestProcessingWorkflowTypedDefinitionBindsExplicitRulesAndSeparateOutputPolicy(t *testing.T) {
	d := processingWorkflow(t)
	normalized, err := Normalize(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Steps) != 0 || normalized.Processing.Definition.Columns[0].Conversion != "identity" || normalized.Processing.Definition.Columns[0].Missing != "preserve" {
		t.Fatal("typed processing lost explicit defaults or acquired delivery")
	}
	wire, hash, _ := digest(normalized)
	d.Processing.Definition.Columns[0].Target = "changed-after-review"
	_, actual, _ := digest(normalized)
	if hash != actual {
		t.Fatal("caller changed reviewed processing rules")
	}
	var decoded Definition
	if Decode(wire, &decoded) != nil {
		t.Fatal("ordinary typed decoder refused processing")
	}
	if _, err = Normalize(decoded); err != nil {
		t.Fatal(err)
	}
}
func TestProcessingWorkflowRefusesImplicitDeliveryScriptsAndUnboundedMeaning(t *testing.T) {
	for _, mutate := range []func(*Definition){
		func(d *Definition) { d.Schema = 1 }, func(d *Definition) { d.Processing = nil },
		func(d *Definition) { d.Processing.Kind = "shell" }, func(d *Definition) { d.Processing.OutputPolicy.Hash = "" },
		func(d *Definition) { d.Processing.Definition.MaxBytes = 0 }, func(d *Definition) { d.Processing.Definition.Engine = "model-decides" },
		func(d *Definition) { d.Processing.Definition.Columns[0].Conversion = "evaluate_code" },
		func(d *Definition) { d.Processing.TargetPath = "/../outside" },
		func(d *Definition) { d.Steps = []Step{{ID: "implicit-send", Kind: "sftp.deliver"}} },
	} {
		d := processingWorkflow(t)
		mutate(&d)
		if _, err := Normalize(d); err == nil {
			t.Fatal("unsupported processing authority/meaning accepted")
		}
	}
	d := processingWorkflow(t)
	wire, _ := json.Marshal(d)
	wire = append(wire[:len(wire)-1], []byte(`,"approved":true}`)...)
	var decoded Definition
	if Decode(wire, &decoded) == nil {
		t.Fatal("artifact instructions acquired workflow approval")
	}
}
