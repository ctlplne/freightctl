package workflow

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestFTPSCollectionSourceUsesExactTypedProtocolAndConnection(t *testing.T) {
	for _, contract := range []string{CollectionContract, ScheduledCollectionContract} {
		source := collectionTestSource()
		source.Kind, source.Contract = "ftps.collect", contract
		if contract == ScheduledCollectionContract {
			source.Manifest = "settlement-{due_utc}.ready.json"
		}
		if err := normalizeCollectionSource(source); err != nil {
			t.Fatal("exact typed FTPS collection source is unavailable", err)
		}
		row := connectionContractRow(t, ftpsConnectionContract())
		source.Connection = Reference{ID: row.ID, Version: row.Version, Hash: row.Hash}
		definition, view, err := collectionSourceConnection(source, row)
		if err != nil || definition.Schema != 2 || view.Protocol != "ftps" || view.Hash != row.Hash || view.FTPS == nil || view.Directory != "/inbox" || view.HostFingerprint != "" || view.KeyFingerprint != "" {
			t.Fatal("FTPS source protocol/view binding differs", err)
		}
		for _, change := range []func(*CollectionSource){
			func(s *CollectionSource) { s.Kind = "sftp.collect" },
			func(s *CollectionSource) { s.Kind = "ftp.collect" },
			func(s *CollectionSource) { s.Connection.Version++ },
			func(s *CollectionSource) { s.Connection.Hash = string(make([]byte, 64)) },
		} {
			mutated := source
			change(&mutated)
			if _, _, err := collectionSourceConnection(mutated, row); err == nil {
				t.Fatal("mixed protocol or changed reference admitted")
			}
		}
		row.State = "revoked"
		if _, _, err := collectionSourceConnection(source, row); err != store.ErrState {
			t.Fatal("revoked source admitted", err)
		}
	}
}

func TestFTPSCollectionGoBrowserCanonicalMetadata(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/ftps-collections.json")
	var fixtures map[string]struct {
		Workflow        store.Configuration `json:"workflow"`
		Preview         CollectionPreview   `json:"preview"`
		WorkflowPreview Preview             `json:"workflow_preview"`
		View            CollectionView      `json:"view"`
	}
	if err != nil || json.Unmarshal(raw, &fixtures) != nil || len(fixtures) != 4 {
		t.Fatal("FTPS canonical metadata fixtures required", err)
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			var definition Definition
			if Decode(fixture.Workflow.Definition, &definition) != nil {
				t.Fatal("typed workflow fixture differs")
			}
			normalized, err := Normalize(definition)
			if err != nil || normalized.Source == nil || normalized.Source.Kind != "ftps.collect" {
				t.Fatal("typed FTPS source lost", err)
			}
			_, hash, err := digest(normalized)
			if err != nil || hash != fixture.Workflow.Hash || hash != fixture.WorkflowPreview.Hash {
				t.Fatal("Go workflow canonical hash differs", err)
			}
			d, err := collectionDefinition(fixture.View.Job)
			if err != nil || d.Source.Kind != "ftps.collect" || d.Connection.Protocol != "ftps" || d.Connection.FTPS == nil || d.Connection.HostFingerprint != "" || d.Connection.KeyFingerprint != "" {
				t.Fatal("FTPS job snapshot changed protocol", err)
			}
			_, hash, err = digest(fixture.Preview.Definition)
			if err != nil || hash != fixture.Preview.Hash || hash != fixture.View.Job.Hash {
				t.Fatal("Go FTPS source/recipient metadata hash differs", err)
			}
			for i, step := range normalized.Steps {
				if (step.Kind == "ftps.deliver") != (d.Effects[i].Protocol == "ftps") || (d.Effects[i].Protocol == "ftps" && d.Effects[i].FTPS == nil) {
					t.Fatal("source and recipient protocols conflated")
				}
			}
		})
	}
}

func TestFTPSCollectionScheduleSourceRequiresExactRemoteShape(t *testing.T) {
	for _, kind := range []string{"sftp.collect", "ftps.collect"} {
		source := ScheduleSourceSelection{Kind: kind, Pattern: "batch-{due_utc}.ready.json"}
		if !validScheduleSource(source) {
			t.Fatal("typed scheduled collection unavailable", kind)
		}
		source.Recursive = true
		if validScheduleSource(source) {
			t.Fatal("recursive manifest source accepted")
		}
	}
	if validScheduleSource(ScheduleSourceSelection{Kind: "ftp.collect", Pattern: "batch-{due_utc}.ready.json"}) {
		t.Fatal("plaintext source inferred from FTPS")
	}
}

func TestFTPSHandoffSyntheticBrowserWireMatchesGoEncoding(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/ftps-handoff-effects.json")
	var fixture struct {
		Cases []struct {
			Name     string              `json:"name"`
			Workflow store.Configuration `json:"workflow"`
			Effects  []Effect            `json:"base_effects"`
			Expected json.RawMessage     `json:"handoff_effects"`
		} `json:"cases"`
	}
	if err != nil || json.Unmarshal(raw, &fixture) != nil || len(fixture.Cases) != 2 {
		t.Fatal("synthetic FTPS handoff wire vectors required", err)
	}
	for _, f := range fixture.Cases {
		t.Run(f.Name, func(t *testing.T) {
			var d Definition
			if Decode(f.Workflow.Definition, &d) != nil {
				t.Fatal("typed workflow required")
			}
			d, err := Normalize(d)
			_, hash, hashErr := digest(d)
			if err != nil || hashErr != nil || hash != f.Workflow.Hash || d.Schema != 2 || len(f.Effects) != len(d.Steps) {
				t.Fatal("synthetic workflow canonical identity differs", err, hashErr)
			}
			wire := make([]CollectionHandoffEffect, 0, len(f.Effects))
			for i, effect := range f.Effects {
				if effect.Protocol != "ftps" || effect.FTPS == nil || effect.HostFingerprint != "" || effect.User == "" || effect.Connection != d.Steps[i].Connection {
					t.Fatal("typed public FTPS recipient changed")
				}
				wire = append(wire, CollectionHandoffEffect{Effect: effect, User: effect.User, KeyFingerprint: ""})
			}
			encoded, err := json.Marshal(wire)
			if err != nil || !jsonEqual(encoded, f.Expected) {
				t.Fatal("Go embedded effect/user wire encoding differs from browser vector", err)
			}
		})
	}
}
