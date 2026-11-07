package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func mcpWorkflowAttemptFixture(t testing.TB, schema int) (*store.RecordProjection, checks.ProjectionDefinition) {
	t.Helper()
	hash := secure.Digest([]byte("synthetic independently approved contract"))
	source := store.File{ID: secure.NewID(), Size: 12, SHA256: hash, Policy: store.CSVIntakePrefix + hash, EventID: secure.NewID()}
	input := store.OnboardingReference{ID: secure.NewID(), Version: 1, Hash: hash}
	output := store.OnboardingReference{ID: secure.NewID(), Version: 2, Hash: hash}
	plan := checks.ProjectionPlan{Schema: schema, Profile: checks.ScopedProjectionProfile, SourcePolicy: input, Context: checks.RecheckPlan{Root: "/SYNTHETIC_PRIVATE_ROOT", Authority: 7, Reason: "SYNTHETIC_PRIVATE_REASON", StorageID: secure.NewID(), Policy: output, Source: checks.RecheckSource{File: source}}}
	producer := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: 7, RootPolicyDigest: secure.Digest([]byte(plan.Context.Root))}
	binding := store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: output.ID, Version: output.Version, Hash: output.Hash, Publisher: secure.NewID(), Producer: producer}
	if schema == 3 || schema == 4 {
		plan.Profile = checks.ProducerProjectionProfile
		plan.OutputBinding = &binding
	}
	if schema == 4 {
		plan.Profile = checks.ComposedProducerProjectionProfile
		originBinding := binding
		originBinding.PolicyID, originBinding.Version, originBinding.Hash = input.ID, input.Version, input.Hash
		plan.SourceOrigin = &store.ProducedSource{Profile: "owned-produced-source-v1", File: source, ProjectionID: secure.NewID(), ProjectionHash: hash, Producer: originBinding}
	}
	d := checks.ProjectionDefinition{Schema: schema, Plan: plan, Slots: []string{secure.NewID(), secure.NewID(), secure.NewID()}, Workflow: &store.ProcessingWorkflowBinding{WorkflowID: secure.NewID(), Version: 1, Hash: hash, RunID: secure.NewID(), StepID: "private_step"}}
	wire, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	outputFile := store.File{ID: d.Slots[0], Size: 16, SHA256: hash, Policy: store.JSONRecordsIntakePrefix + hash, EventID: secure.NewID()}
	result, err := json.Marshal(checks.ProjectionOutput{Kind: "record_projection_output", File: outputFile, Acceptance: "durable-held-pending-checks-and-release"})
	if err != nil {
		t.Fatal(err)
	}
	return &store.RecordProjection{ID: secure.NewID(), SourceID: source.ID, FileID: outputFile.ID, Definition: wire, Hash: secure.Digest(wire), State: "completed", Revision: 3, Attempts: 1, Result: result}, d
}

func TestMCPWorkflowAttemptMetadataAcceptsExactProducerProfilesWithoutDisclosingPrivatePlans(t *testing.T) {
	for _, schema := range []int{2, 3, 4} {
		r, d := mcpWorkflowAttemptFixture(t, schema)
		facts, err := mcpProjectionProfileFacts(r, true, false, "original-command-receipt", d.Workflow.RunID)
		if err != nil || facts["profile"] != d.Plan.Profile || facts["current"] != "not-checked" || facts["acceptance"] != "durable-held-pending-checks-and-release" || facts["release_inherited"] != false {
			t.Fatal("supported workflow attempt metadata was refused or implied release", schema, err)
		}
		raw, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"SYNTHETIC_PRIVATE_", "private_step", `"staging_slots"`, `"namespace_root"`, `"storage_id"`, `"output_binding"`, `"source_origin"`, `"publisher"`, `"definition"`} {
			if strings.Contains(string(raw), private) {
				t.Fatal("private processing plan entered model context", schema)
			}
		}
		if _, err = mcpProjectionProfileFacts(r, false, true, "current-observation", secure.NewID()); err == nil {
			t.Fatal("attempt metadata adopted another run", schema)
		}
		if _, err = mcpProjectionFacts(r, false, true, "current-observation"); err == nil {
			t.Fatal("direct projection tools adopted a workflow-bound attempt", schema)
		}
	}
}

func TestMCPWorkflowAttemptMetadataRefusesRehashedBindingAndLineageSubstitutions(t *testing.T) {
	for _, schema := range []int{3, 4} {
		mutations := []func(*checks.ProjectionDefinition){
			func(d *checks.ProjectionDefinition) { d.Schema = 2 },
			func(d *checks.ProjectionDefinition) { d.Plan.Schema = 5 },
			func(d *checks.ProjectionDefinition) { d.Plan.OutputBinding = nil },
			func(d *checks.ProjectionDefinition) { d.Plan.OutputBinding.Producer.AuthorityRevision++ },
			func(d *checks.ProjectionDefinition) {
				d.Plan.OutputBinding.Producer.RootPolicyDigest = secure.Digest([]byte("/other"))
			},
			func(d *checks.ProjectionDefinition) { d.Plan.OutputBinding.Version++ },
			func(d *checks.ProjectionDefinition) {
				d.Plan.OutputBinding.Hash = secure.Digest([]byte("other output"))
			},
			func(d *checks.ProjectionDefinition) { d.Workflow = nil },
			func(d *checks.ProjectionDefinition) { d.Workflow.StepID = "host/path" },
			func(d *checks.ProjectionDefinition) { d.Slots[1] = d.Slots[0] },
			func(d *checks.ProjectionDefinition) { d.Slots[0] = d.Plan.Context.Source.File.ID },
		}
		if schema == 4 {
			mutations = append(mutations,
				func(d *checks.ProjectionDefinition) { d.Plan.SourceOrigin = nil },
				func(d *checks.ProjectionDefinition) { d.Plan.SourceOrigin.File.EventID = "" },
				func(d *checks.ProjectionDefinition) { d.Plan.SourceOrigin.Producer.Producer.Actor = secure.NewID() },
				func(d *checks.ProjectionDefinition) { d.Plan.SourceOrigin.Producer.PolicyID = secure.NewID() },
			)
		}
		for _, mutate := range mutations {
			r, d := mcpWorkflowAttemptFixture(t, schema)
			run := d.Workflow.RunID
			mutate(&d)
			wire, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			r.Definition, r.Hash = wire, secure.Digest(wire)
			if _, err = mcpProjectionProfileFacts(r, false, true, "current-observation", run); err == nil {
				t.Fatal("rehashed invalid producer/lineage/workflow/slot binding entered model context", schema)
			}
		}
	}
}
