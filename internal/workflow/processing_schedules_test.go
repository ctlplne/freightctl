package workflow

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingScheduleBindsOneOwnedCheckedTaskWithoutDeliveryEffectsOrLegacyReinterpretation(t *testing.T) {
	w, err := Normalize(processingWorkflow(t))
	if err != nil {
		t.Fatal(err)
	}
	source := ScheduleSourceSelection{Kind: ProcessingScheduleSource, Directory: "/incoming", Pattern: "*.csv"}
	binding, err := processingScheduleBinding(&w, source)
	if err != nil || binding == nil || binding.Profile != "owned-record-processing-schedule-v1" || !reflect.DeepEqual(binding.Task, *w.Processing) {
		t.Fatal("schedule lost separately approved task meaning", err)
	}
	w.Processing.Definition.Columns[0].Target = "changed-after-review"
	if binding.Task.Definition.Columns[0].Target == "changed-after-review" {
		t.Fatal("caller changed reviewed schedule task")
	}
	for _, mutate := range []func(*Definition, *ScheduleSourceSelection){
		func(w *Definition, _ *ScheduleSourceSelection) { w.Schema = 1 },
		func(w *Definition, _ *ScheduleSourceSelection) { w.Processing = nil },
		func(w *Definition, _ *ScheduleSourceSelection) { w.Steps = []Step{{ID: "send", Kind: "sftp.deliver"}} },
		func(_ *Definition, s *ScheduleSourceSelection) { s.Kind = "" },
		func(_ *Definition, s *ScheduleSourceSelection) { s.Kind = "sftp.collect" },
		func(_ *Definition, s *ScheduleSourceSelection) { s.Pattern = "../outside" },
	} {
		changed := processingWorkflow(t)
		selected := source
		mutate(&changed, &selected)
		if _, err := processingScheduleBinding(&changed, selected); err == nil {
			t.Fatal("incompatible schedule acquired processing authority")
		}
	}
	if !validScheduleSource(source) {
		t.Fatal("owned checked record source refused")
	}
}

func TestProcessingScheduleGoBrowserIndependentCanonicalDefinitionAndLegacyRefusal(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/processing-schedule.json")
	if err != nil {
		t.Fatal(err)
	}
	var sample struct {
		Definition ScheduleDefinition `json:"definition"`
		Hash       string             `json:"definition_hash"`
	}
	if Decode(raw, &sample) != nil {
		t.Fatal("independent calendar fixture")
	}
	wire, hash, err := digest(sample.Definition)
	if err != nil || hash != sample.Hash {
		t.Fatal("Go and independent calendar/task meaning differ", err)
	}
	record := &store.Schedule{ScheduleSummary: store.ScheduleSummary{Name: sample.Definition.Name, Hash: hash}, Definition: wire}
	if _, _, err := scheduleDefinition(record); err != nil {
		t.Fatal("complete typed processing calendar refused", err)
	}
	for _, mutate := range []func(*ScheduleDefinition){
		func(d *ScheduleDefinition) { d.Schema = 1 },
		func(d *ScheduleDefinition) { d.Processing = nil },
		func(d *ScheduleDefinition) { d.Source.Kind = "" },
		func(d *ScheduleDefinition) { d.Processing.Profile = "implicit-execution" },
	} {
		var changed ScheduleDefinition
		if json.Unmarshal(wire, &changed) != nil {
			t.Fatal("fixture")
		}
		mutate(&changed)
		record.Definition, record.Hash, _ = digest(changed)
		if _, _, err := scheduleDefinition(record); err == nil {
			t.Fatal("calendar profile inherited unsupported authority")
		}
	}
}
