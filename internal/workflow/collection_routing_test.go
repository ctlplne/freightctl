package workflow

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

type capturedRoutingBrowserFixture struct {
	View          CollectionView             `json:"view"`
	Workflow      store.Configuration        `json:"workflow"`
	Selection     CollectionRoutingSelection `json:"selection"`
	Preview       CollectionRoutingPreview   `json:"preview"`
	Authorization store.CollectionRouting    `json:"authorization"`
	Prior         *store.CollectionRouting   `json:"prior"`
	InputPreview  RunPreview                 `json:"input_preview"`
}

// A typed Go fixture is also evaluated by the independent browser compiler and
// PostgreSQL serializer. Dummy references never authorize a real peer or file.
func TestCapturedRoutingBrowserFingerprintsAndOriginalInputContract(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/collections.json")
	if err != nil {
		t.Fatal(err)
	}
	var base map[string]struct {
		View     CollectionView      `json:"view"`
		Workflow store.Configuration `json:"workflow"`
		Run      struct {
			Run store.WorkflowRun `json:"run"`
		} `json:"run"`
	}
	if json.Unmarshal(data, &base) != nil {
		t.Fatal("collection fixture")
	}
	f := base["plain"]
	var original Definition
	if Decode(f.Workflow.Definition, &original) != nil || len(f.View.Inputs) != 1 || f.View.Job.ManifestHash == nil {
		t.Fatal("original collection fixture")
	}
	f.View.Inputs[0].State, f.View.Inputs[0].RunID = "accepted", nil
	f.View.Inputs[0].Revision = 2
	var manifest CollectionManifest
	if Decode(f.View.Job.Manifest, &manifest) != nil {
		t.Fatal("original manifest")
	}
	var jobDefinition CollectionDefinition
	if Decode(f.View.Job.Definition, &jobDefinition) != nil {
		t.Fatal("original job definition")
	}
	fixtures := map[string]capturedRoutingBrowserFixture{}
	var prior *store.CollectionRouting
	for index, name := range []string{"send", "local"} {
		w := f.Workflow
		w.Version += index + 1
		d := original
		d.Schema = 2
		d.Program = &Program{Nodes: []ProgramNode{{Kind: "deliver", Step: original.Steps[0].ID}}}
		if name == "local" {
			d.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "reviewed_local_outcome"}}}
		}
		d, err = Normalize(d)
		if err != nil {
			t.Fatal(err)
		}
		w.Definition, w.Hash, err = digest(d)
		if err != nil {
			t.Fatal(err)
		}
		wf := Reference{ID: w.ID, Version: w.Version, Hash: w.Hash}
		input := f.View.Inputs[0]
		facts := RoutingFacts{File: f.Run.Run.Source, Source: &RoutingSource{CollectionID: f.View.Job.ID, ManifestHash: *f.View.Job.ManifestHash, Name: input.Name, BatchID: manifest.Batch, Count: len(manifest.Files), Index: 0}}
		plan, err := CompileProgram(d, facts)
		if err != nil {
			t.Fatal(err)
		}
		_, ph, err := digest(plan)
		if err != nil {
			t.Fatal(err)
		}
		definition := CollectionRoutingDefinition{Schema: 1, Collection: CollectionRoutingJob{ID: f.View.Job.ID, Revision: f.View.Job.Revision, Hash: f.View.Job.Hash}, OriginalWorkflow: jobDefinition.Workflow, Workflow: wf, ManifestHash: *f.View.Job.ManifestHash, Authority: jobDefinition.Authority, StorageID: jobDefinition.StorageID, Root: "/", Inputs: []CollectionRoutingBinding{{InputID: input.ID, FileID: *input.FileID, PlanHash: ph}}, Previous: routingReference(prior)}
		if err = validateCollectionRoutingDefinition(definition); err != nil {
			t.Fatal(err)
		}
		raw, hash, err := digest(definition)
		if err != nil {
			t.Fatal(err)
		}
		a := store.CollectionRouting{ID: fmt.Sprintf("000000%02d-1111-4111-8111-111111111111", 40+index), JobID: f.View.Job.ID, Version: index + 1, Definition: raw, Hash: hash, State: "proposed", Revision: 1}
		selected := []Effect{}
		if len(plan.Steps) > 0 {
			selected = append(selected, jobDefinition.Effects[0])
		}
		fixtures[name] = capturedRoutingBrowserFixture{View: f.View, Workflow: w, Selection: CollectionRoutingSelection{Collection: Decision{Hash: f.View.Job.Hash, Revision: f.View.Job.Revision}, Workflow: wf, Authority: definition.Authority}, Preview: CollectionRoutingPreview{Definition: definition, Hash: hash, ApprovalRequired: true}, Authorization: a, Prior: prior, InputPreview: RunPreview{Workflow: wf, Source: facts.File, Potential: jobDefinition.Effects, Selected: selected, Plan: plan, PlanHash: ph}}
		approved := a
		approved.State, approved.Revision, approved.ApprovalAuthority = "approved", 2, definition.Authority
		prior = &approved
	}
	encoded, err := json.MarshalIndent(fixtures, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if ref := os.Getenv("FREIGHTCTL_WRITE_CAPTURED_ROUTING_FIXTURE"); ref != "" {
		file, err := os.OpenFile(ref, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(append(encoded, '\n')); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := os.ReadFile("../../web/tests/fixtures/collection-routing.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if json.Compact(&compact, expected) != nil {
		t.Fatal("captured routing fixture JSON")
	}
	actual, _ := json.Marshal(fixtures)
	if !bytes.Equal(actual, compact.Bytes()) {
		t.Fatal("Go definition, plan or original-input fixture fingerprint changed")
	}
}

func routingAuthorizationFixture() CollectionRoutingDefinition {
	return CollectionRoutingDefinition{
		Schema:           1,
		Collection:       CollectionRoutingJob{ID: "00000000-0000-0000-0000-000000000001", Revision: 4, Hash: strings.Repeat("1", 64)},
		OriginalWorkflow: Reference{ID: "00000000-0000-0000-0000-000000000002", Version: 1, Hash: strings.Repeat("2", 64)},
		Workflow:         Reference{ID: "00000000-0000-0000-0000-000000000002", Version: 2, Hash: strings.Repeat("3", 64)},
		ManifestHash:     strings.Repeat("4", 64), Authority: 7, StorageID: "00000000-0000-0000-0000-000000000003", Root: "/",
		Inputs: []CollectionRoutingBinding{{InputID: "00000000-0000-0000-0000-000000000004", FileID: "00000000-0000-0000-0000-000000000005", PlanHash: strings.Repeat("5", 64)}},
	}
}

func TestCapturedRoutingAuthorizationBoundsAndRejectsAmbiguousInputOwnership(t *testing.T) {
	for name, mutate := range map[string]func(*CollectionRoutingDefinition){
		"missing inputs": func(d *CollectionRoutingDefinition) { d.Inputs = nil },
		"duplicate input": func(d *CollectionRoutingDefinition) {
			d.Inputs = append(d.Inputs, CollectionRoutingBinding{InputID: d.Inputs[0].InputID, FileID: "00000000-0000-0000-0000-000000000006", PlanHash: strings.Repeat("6", 64)})
		},
		"duplicate file": func(d *CollectionRoutingDefinition) {
			d.Inputs = append(d.Inputs, CollectionRoutingBinding{InputID: "00000000-0000-0000-0000-000000000006", FileID: d.Inputs[0].FileID, PlanHash: strings.Repeat("6", 64)})
		},
		"foreign workflow family":  func(d *CollectionRoutingDefinition) { d.Workflow.ID = d.StorageID },
		"missing plan fingerprint": func(d *CollectionRoutingDefinition) { d.Inputs[0].PlanHash = "" },
		"missing capture revision": func(d *CollectionRoutingDefinition) { d.Collection.Revision = 0 },
		"invalid previous decision": func(d *CollectionRoutingDefinition) {
			d.Previous = &CollectionRoutingReference{ID: d.StorageID, Version: 1, Hash: d.ManifestHash}
		},
		"nested namespace": func(d *CollectionRoutingDefinition) { d.Root = "/other" },
		"unknown schema":   func(d *CollectionRoutingDefinition) { d.Schema = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			d := routingAuthorizationFixture()
			mutate(&d)
			if validateCollectionRoutingDefinition(d) == nil {
				t.Fatal("ambiguous or incomplete routing authorization accepted")
			}
		})
	}
	d := routingAuthorizationFixture()
	d.Inputs = nil
	for i := 0; i < 64; i++ {
		d.Inputs = append(d.Inputs, CollectionRoutingBinding{InputID: fmt.Sprintf("00000000-0000-0000-0000-%012d", 100+i), FileID: fmt.Sprintf("00000000-0000-0000-0000-%012d", 200+i), PlanHash: strings.Repeat("6", 64)})
	}
	d.Previous = &CollectionRoutingReference{ID: d.StorageID, Version: 3, Hash: d.ManifestHash, Revision: 8}
	if err := validateCollectionRoutingDefinition(d); err != nil {
		t.Fatal("a complete 64-input authorization must fit the existing budget", err)
	}
	raw, _, err := digest(d)
	if err != nil || len(raw) > 24<<10 {
		t.Fatal("authorization exceeds the unchanged definition budget", len(raw), err)
	}
	d.Inputs = append(d.Inputs, CollectionRoutingBinding{InputID: "00000000-0000-0000-0000-000000000999", FileID: "00000000-0000-0000-0000-000000000998", PlanHash: strings.Repeat("7", 64)})
	if validateCollectionRoutingDefinition(d) == nil {
		t.Fatal("unbounded batch authorization accepted")
	}
}

func TestCapturedRoutingAuthorizationFingerprintBindsOriginalEvidenceAndPriorDecision(t *testing.T) {
	for name, mutate := range map[string]func(*CollectionRoutingDefinition){
		"job":                        func(d *CollectionRoutingDefinition) { d.Collection.ID = d.StorageID },
		"job revision":               func(d *CollectionRoutingDefinition) { d.Collection.Revision++ },
		"job definition":             func(d *CollectionRoutingDefinition) { d.Collection.Hash = d.ManifestHash },
		"original workflow":          func(d *CollectionRoutingDefinition) { d.OriginalWorkflow.Version++ },
		"target workflow":            func(d *CollectionRoutingDefinition) { d.Workflow.Version++ },
		"manifest":                   func(d *CollectionRoutingDefinition) { d.ManifestHash = d.Collection.Hash },
		"actor authority":            func(d *CollectionRoutingDefinition) { d.Authority++ },
		"storage":                    func(d *CollectionRoutingDefinition) { d.StorageID = d.Collection.ID },
		"input":                      func(d *CollectionRoutingDefinition) { d.Inputs[0].InputID = d.StorageID },
		"file":                       func(d *CollectionRoutingDefinition) { d.Inputs[0].FileID = d.StorageID },
		"selected plan":              func(d *CollectionRoutingDefinition) { d.Inputs[0].PlanHash = d.ManifestHash },
		"prior decision revocation":  func(d *CollectionRoutingDefinition) { d.Previous.Revision++ },
		"prior decision replacement": func(d *CollectionRoutingDefinition) { d.Previous.ID = d.Collection.ID },
	} {
		t.Run(name, func(t *testing.T) {
			d := routingAuthorizationFixture()
			d.Previous = &CollectionRoutingReference{ID: d.StorageID, Version: 3, Hash: d.ManifestHash, Revision: 8}
			raw, hash, err := digest(d)
			if err != nil {
				t.Fatal(err)
			}
			r := &store.CollectionRouting{JobID: d.Collection.ID, Definition: raw, Hash: hash}
			if _, err = collectionRoutingDefinition(r); err != nil {
				t.Fatal("original reviewed definition rejected", err)
			}
			mutate(&d)
			r.Definition, _, err = digest(d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = collectionRoutingDefinition(r); err == nil {
				t.Fatal("a changed capture, choice or prior decision kept the reviewed fingerprint")
			}
		})
	}
	d := routingAuthorizationFixture()
	raw, hash, _ := digest(d)
	var decoded CollectionRoutingDefinition
	if err := Decode(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, got, _ := digest(decoded); got != hash {
		t.Fatal("reloading the reviewed definition changed its fingerprint")
	}
	var unknown map[string]json.RawMessage
	if json.Unmarshal(raw, &unknown) != nil {
		t.Fatal("fixture")
	}
	unknown["extend_deadline"] = json.RawMessage(`true`)
	raw, _ = json.Marshal(unknown)
	if Decode(raw, &decoded) == nil {
		t.Fatal("an authorization cannot smuggle a cutoff extension")
	}
}
