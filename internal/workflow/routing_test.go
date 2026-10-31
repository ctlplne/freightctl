package workflow

import (
	"bytes"
	"encoding/json"
	"github.com/ctlplne/freightctl/internal/store"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func routingDefinition(t *testing.T) Definition {
	t.Helper()
	source := collectionTestSource()
	d := Definition{Schema: 2, Name: "Settlement routes", Source: &source, Steps: []Step{
		{ID: "north", Kind: "sftp.deliver", Connection: source.Connection, Filename: "north.csv"},
		{ID: "south", Kind: "sftp.deliver", Connection: source.Connection, Filename: "south.csv"},
		{ID: "audit", Kind: "sftp.deliver", Connection: source.Connection, Filename: "audit.csv"},
	}}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	object["program"] = map[string]any{"nodes": []any{
		map[string]any{"kind": "if", "when": map[string]any{"op": "glob", "field": "source.name", "text": "north-*.csv"}, "then": []any{
			map[string]any{"kind": "for_each", "variable": "recipient", "steps": []string{"north", "audit"}, "body": []any{map[string]any{"kind": "deliver", "step_variable": "recipient"}}},
		}, "else": []any{map[string]any{"kind": "keep_local", "reason": "unmatched_settlement"}}},
	}}
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err = Decode(data, &d); err != nil {
		t.Fatal("typed workflow cannot represent reviewed routing branches and bounded loops", err)
	}
	return d
}

func TestBoundedRoutingProgramAcceptsReviewedBranchAndForeachCatalog(t *testing.T) {
	d := routingDefinition(t)
	normalized, err := Normalize(d)
	if err != nil || normalized.Schema != 2 || len(normalized.Steps) != 3 {
		t.Fatal("approved finite routing program was rejected", normalized, err)
	}
}

func routingTestFacts() RoutingFacts {
	return RoutingFacts{File: store.File{ID: "00000000-0000-0000-0000-000000000002", Size: 3, SHA256: strings.Repeat("a", 64), Policy: "integrity-only-v1", EventID: "00000000-0000-0000-0000-000000000003"}, Source: &RoutingSource{CollectionID: "00000000-0000-0000-0000-000000000004", ManifestHash: strings.Repeat("b", 64), Name: "north-settlement.csv", BatchID: "00000000-0000-0000-0000-000000000005", Count: 2, Index: 0}}
}
func TestRoutingCompilerFreezesBoundedLoopChoicesAndExplicitLocalDisposition(t *testing.T) {
	d := routingDefinition(t)
	facts := routingTestFacts()
	p, err := CompileProgram(d, facts)
	if err != nil || !reflect.DeepEqual(p.Steps, []string{"north", "audit"}) || p.LocalReason != "" || len(p.Decisions) != 4 {
		t.Fatal(p, err)
	}
	if p.Decisions[0].Matched == nil || !*p.Decisions[0].Matched || p.Decisions[2].Path != "0.then.0[0].body.0" || p.Decisions[3].Step != "audit" {
		t.Fatal("unexplained or reordered routing choice", p)
	}
	a, hash, err := digest(p)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := CompileProgram(d, facts)
	if err != nil {
		t.Fatal(err)
	}
	b, replayHash, _ := digest(replay)
	if !bytes.Equal(a, b) || hash != replayHash {
		t.Fatal("same approved program and facts changed their plan")
	}
	facts.Source.Name = "south-settlement.csv"
	if p.Facts.Source.Name != "north-settlement.csv" {
		t.Fatal("caller mutation changed frozen plan facts")
	}
	local, err := CompileProgram(d, facts)
	if err != nil || len(local.Steps) != 0 || local.LocalReason != "unmatched_settlement" || len(local.Decisions) != 2 {
		t.Fatal("unmatched file lacked explicit local disposition", local, err)
	}
}
func TestRoutingCompilerRefusesIncompleteFactsAndAccidentalOrRepeatedEffects(t *testing.T) {
	for name, mutate := range map[string]func(*Definition, *RoutingFacts){
		"missing-source":               func(_ *Definition, f *RoutingFacts) { f.Source = nil },
		"wrong-file-digest":            func(_ *Definition, f *RoutingFacts) { f.File.SHA256 = "not-a-digest" },
		"unbounded-file":               func(_ *Definition, f *RoutingFacts) { f.File.Size = 1 << 31 },
		"out-of-batch-index":           func(_ *Definition, f *RoutingFacts) { f.Source.Index = f.Source.Count },
		"source-traversal":             func(_ *Definition, f *RoutingFacts) { f.Source.Name = "../north.csv" },
		"source-shell-text":            func(_ *Definition, f *RoutingFacts) { f.Source.Name = "north-$(recipient).csv" },
		"ready-manifest-as-payload":    func(_ *Definition, f *RoutingFacts) { f.Source.Name = "north.ready.json" },
		"missing-explicit-disposition": func(d *Definition, f *RoutingFacts) { d.Program.Nodes[0].Else = nil; f.Source.Name = "south.csv" },
		"duplicate-selected-step": func(d *Definition, _ *RoutingFacts) {
			d.Program.Nodes[0].Then = append(d.Program.Nodes[0].Then, ProgramNode{Kind: "deliver", Step: "north"})
		},
		"mixed-local-and-send": func(d *Definition, _ *RoutingFacts) {
			d.Program.Nodes = append(d.Program.Nodes, ProgramNode{Kind: "keep_local", Reason: "also_local"})
		},
		"duplicate-local": func(d *Definition, f *RoutingFacts) {
			d.Program.Nodes = append(d.Program.Nodes, ProgramNode{Kind: "keep_local", Reason: "another_local"})
			f.Source.Name = "south.csv"
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := routingDefinition(t)
			facts := routingTestFacts()
			mutate(&d, &facts)
			if _, err := CompileProgram(d, facts); err == nil {
				t.Fatal("ambiguous facts or effects produced an executable plan")
			}
		})
	}
}
func TestRoutingProgramNormalizationRefusesAuthorityInjectionAndUnboundedExpansion(t *testing.T) {
	for name, mutate := range map[string]func(*Definition){
		"schema-one-program":        func(d *Definition) { d.Schema = 1 },
		"missing-program":           func(d *Definition) { d.Program = nil },
		"unknown-node":              func(d *Definition) { d.Program.Nodes[0].Kind = "exec" },
		"hidden-recipient":          func(d *Definition) { d.Program.Nodes[0].Step = "south" },
		"unregistered-catalog-step": func(d *Definition) { d.Program.Nodes[0].Then[0].Steps = []string{"external-recipient"} },
		"duplicate-loop-item":       func(d *Definition) { d.Program.Nodes[0].Then[0].Steps = []string{"north", "north"} },
		"unbound-variable":          func(d *Definition) { d.Program.Nodes[0].Then[0].Body[0].StepVariable = "unbound" },
		"two-target-selectors":      func(d *Definition) { d.Program.Nodes[0].Then[0].Body[0].Step = "south" },
		"arbitrary-field":           func(d *Definition) { d.Program.Nodes[0].When.Field = "model.approved_recipient" },
		"number-as-name": func(d *Definition) {
			n := int64(1)
			d.Program.Nodes[0].When.Text = nil
			d.Program.Nodes[0].When.Number = &n
		},
		"regex-instead-of-glob":       func(d *Definition) { s := "^(north|south).*"; d.Program.Nodes[0].When.Text = &s },
		"unavailable-collection-fact": func(d *Definition) { d.Source = nil },
		"variable-shadow": func(d *Definition) {
			body := d.Program.Nodes[0].Then[0]
			d.Program.Nodes[0].Then[0].Body = []ProgramNode{body}
		},
		"excess-depth": func(d *Definition) {
			node := d.Program.Nodes[0]
			for i := 0; i < 4; i++ {
				node = ProgramNode{Kind: "if", When: node.When, Then: []ProgramNode{node}}
			}
			d.Program.Nodes = []ProgramNode{node}
		},
		"excess-expanded-visits": func(d *Definition) {
			body := make([]ProgramNode, 12)
			for i := range body {
				body[i] = ProgramNode{Kind: "deliver", StepVariable: "outer"}
			}
			d.Program.Nodes = []ProgramNode{{Kind: "for_each", Variable: "outer", Steps: []string{"north", "south", "audit"}, Body: []ProgramNode{{Kind: "for_each", Variable: "middle", Steps: []string{"north", "south", "audit"}, Body: []ProgramNode{{Kind: "for_each", Variable: "inner", Steps: []string{"north", "south", "audit"}, Body: body}}}}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := routingDefinition(t)
			mutate(&d)
			if _, err := Normalize(d); err == nil {
				t.Fatal("unsupported authority or unbounded work accepted")
			}
		})
	}
}
func TestRoutingConditionsUseExactIntegerAndScopedStringSemantics(t *testing.T) {
	d := routingDefinition(t)
	large := int64(9007199254740993)
	five := int64(5)
	two := int64(2)
	name := "north"
	glob := "north-??????????.csv"
	digestValue := strings.Repeat("a", 64)
	d.Program.Nodes = []ProgramNode{{Kind: "for_each", Variable: "destination", Steps: []string{"north", "audit"}, Body: []ProgramNode{{Kind: "if", When: &Condition{Op: "all", All: []Condition{
		{Op: "lt", Field: "file.size_bytes", Number: &large}, {Op: "le", Field: "file.size_bytes", Number: &five}, {Op: "ge", Field: "source.file_count", Number: &two}, {Op: "eq", Field: "file.sha256", Text: &digestValue},
		{Op: "any", Any: []Condition{{Op: "eq", Variable: "destination", Text: &name}, {Op: "not", Not: &Condition{Op: "eq", Variable: "destination", Text: &name}}}},
		{Op: "glob", Field: "source.name", Text: &glob},
	}}, Then: []ProgramNode{{Kind: "deliver", StepVariable: "destination"}}}}}}
	p, err := CompileProgram(d, routingTestFacts())
	if err != nil || !reflect.DeepEqual(p.Steps, []string{"north", "audit"}) {
		t.Fatal(p, err)
	}
}
func TestRoutingNormalizationOwnsItsCatalogAndControlSnapshot(t *testing.T) {
	d := routingDefinition(t)
	normalized, err := Normalize(d)
	if err != nil {
		t.Fatal(err)
	}
	before, hash, _ := digest(normalized)
	d.Steps[0].Filename = "changed.csv"
	*d.Program.Nodes[0].When.Text = "changed-*"
	d.Program.Nodes[0].Then[0].Steps[0] = "south"
	after, afterHash, _ := digest(normalized)
	if !bytes.Equal(before, after) || hash != afterHash {
		t.Fatal("caller mutation changed the normalized routing catalog or program")
	}
}

func TestRoutingIntegerThresholdsRoundTripWithoutBrowserFloatRounding(t *testing.T) {
	value := int64(9007199254740993)
	c := Condition{Op: "lt", Field: "file.size_bytes", Number: &value}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"number":"9007199254740993"`)) {
		t.Fatal("threshold crossed a floating-point JSON boundary", string(data))
	}
	var decoded Condition
	if err = Decode(data, &decoded); err != nil || decoded.Number == nil || *decoded.Number != value {
		t.Fatal(decoded, err)
	}
	if err = Decode([]byte(`{"op":"lt","field":"file.size_bytes","number":9007199254740993}`), &decoded); err == nil {
		t.Fatal("unsafe unquoted numeric rule was accepted")
	}
}

type routingGolden struct {
	Definition     Definition     `json:"definition"`
	DefinitionHash string         `json:"definition_hash"`
	Facts          RoutingFacts   `json:"facts"`
	Plan           *ExecutionPlan `json:"plan"`
	PlanHash       string         `json:"plan_hash"`
}

func TestRoutingCanonicalPlansMatchIndependentContractFixtures(t *testing.T) {
	fixtures := map[string]routingGolden{}
	add := func(name string, d Definition, facts RoutingFacts) {
		t.Helper()
		normalized, err := Normalize(d)
		if err != nil {
			t.Fatal(name, err)
		}
		plan, err := CompileProgram(normalized, facts)
		if err != nil {
			t.Fatal(name, err)
		}
		_, dh, _ := digest(normalized)
		_, ph, _ := digest(plan)
		fixtures[name] = routingGolden{Definition: normalized, DefinitionHash: dh, Facts: facts, Plan: plan, PlanHash: ph}
	}
	add("north_loop", routingDefinition(t), routingTestFacts())
	facts := routingTestFacts()
	facts.Source.Name = "south-settlement.csv"
	add("explicit_local", routingDefinition(t), facts)
	cases := []struct {
		op     string
		field  string
		text   string
		number string
	}{
		{"eq", "source.name", "north-settlement.csv", ""}, {"ne", "source.name", "south.csv", ""}, {"prefix", "source.name", "north-", ""}, {"suffix", "source.name", ".csv", ""}, {"glob", "source.name", "north-??????????.csv", ""},
		{"eq", "file.size_bytes", "", "3"}, {"ne", "file.size_bytes", "", "4"}, {"lt", "file.size_bytes", "", "9007199254740993"}, {"le", "file.size_bytes", "", "3"}, {"gt", "file.size_bytes", "", "2"}, {"ge", "file.size_bytes", "", "3"},
	}
	for _, item := range cases {
		d := routingDefinition(t)
		condition := Condition{Op: item.op, Field: item.field}
		if item.text != "" {
			text := item.text
			condition.Text = &text
		} else {
			value, err := strconv.ParseInt(item.number, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			condition.Number = &value
		}
		d.Program.Nodes = []ProgramNode{{Kind: "if", When: &condition, Then: []ProgramNode{{Kind: "deliver", Step: "north"}}, Else: []ProgramNode{{Kind: "keep_local", Reason: "condition_false"}}}}
		add("operator_"+item.op+"_"+strings.ReplaceAll(item.field, ".", "_"), d, routingTestFacts())
	}
	d := routingDefinition(t)
	d.Source = nil
	d.Steps = []Step{}
	d.Program = &Program{Nodes: []ProgramNode{{Kind: "keep_local", Reason: "local_policy"}}}
	facts = routingTestFacts()
	facts.Source = nil
	add("local_without_source_or_receiver", d, facts)
	d = routingDefinition(t)
	text := "north"
	d.Program.Nodes = []ProgramNode{{Kind: "for_each", Variable: "destination", Steps: []string{"north", "south", "audit"}, Body: []ProgramNode{{Kind: "if", When: &Condition{Op: "eq", Variable: "destination", Text: &text}, Then: []ProgramNode{{Kind: "deliver", StepVariable: "destination"}}}}}}
	add("scoped_loop_condition", d, routingTestFacts())
	if ref := os.Getenv("FREIGHTCTL_WRITE_ROUTING_FIXTURES"); ref != "" {
		data, err := json.MarshalIndent(fixtures, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		file, err := os.OpenFile(ref, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(append(data, '\n')); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile("../../web/tests/fixtures/routing.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]routingGolden
	if err = Decode(data, &expected); err != nil {
		// The fixture bundle contains several independent bounded documents; each
		// definition/plan still passes its own ordinary Decode and Normalize gate.
		if err = json.Unmarshal(data, &expected); err != nil {
			t.Fatal(err)
		}
	}
	if len(expected) != len(fixtures) {
		t.Fatal("routing contract coverage changed", len(expected), len(fixtures))
	}
	for name, actual := range fixtures {
		a, _, _ := digest(actual)
		b, _, _ := digest(expected[name])
		if !bytes.Equal(a, b) {
			t.Fatal("canonical Go routing fixture differs", name)
		}
	}
}

func FuzzBoundedRoutingProgram(f *testing.F) {
	data, err := os.ReadFile("../../web/tests/fixtures/routing.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixtures map[string]routingGolden
	if err = json.Unmarshal(data, &fixtures); err != nil {
		f.Fatal(err)
	}
	for _, fixture := range fixtures {
		data, err = json.Marshal(fixture.Definition)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"schema_version":2,"name":"injection","steps":[],"program":{"nodes":[{"kind":"exec","command":"send elsewhere"}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var d Definition
		if Decode(data, &d) != nil {
			return
		}
		normalized, err := Normalize(d)
		if err != nil || normalized.Schema != 2 {
			return
		}
		facts := routingTestFacts()
		if normalized.Source == nil {
			facts.Source = nil
		}
		plan, err := CompileProgram(normalized, facts)
		if err != nil {
			return
		}
		if len(plan.Steps) > 16 || len(plan.Decisions) > maxProgramVisits || (len(plan.Steps) == 0) != (plan.LocalReason != "") {
			t.Fatal("compiler escaped its effect or disposition budget")
		}
		seen := map[string]bool{}
		catalog := map[string]bool{}
		for _, s := range normalized.Steps {
			catalog[s.ID] = true
		}
		for _, id := range plan.Steps {
			if !catalog[id] || seen[id] {
				t.Fatal("plan added or duplicated an approved catalog recipient")
			}
			seen[id] = true
		}
		replay, err := CompileProgram(normalized, facts)
		if err != nil {
			t.Fatal("same plan facts became undecidable", err)
		}
		a, _, _ := digest(plan)
		b, _, _ := digest(replay)
		if !bytes.Equal(a, b) {
			t.Fatal("routing depends on mutable or external state")
		}
	})
}
