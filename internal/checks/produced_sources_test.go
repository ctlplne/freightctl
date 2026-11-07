package checks

import (
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestComposedProducerProjectionRequiresExactOwnedSourceAndSeparateOutputBinding(t *testing.T) {
	base, row, rules, now := projectionReviewFixture(t)
	base.Plan.Source.File.EventID = secure.NewID()
	base.Plan.Source.Check.Binding.File = base.Plan.Source.File
	row.Binding, _, _ = canonical(base.Plan.Source.Check.Binding)
	base.PreviousPolicy.State, base.CurrentPolicy.State = "output_active", "output_active"
	actor := store.ExchangeParticipant{Tenant: secure.NewID(), Partner: secure.NewID(), Actor: secure.NewID(), AuthorityRevision: base.Plan.Authority, RootPolicyDigest: secure.Digest([]byte(base.Plan.Root))}
	input := base.PreviousPolicy.Reference
	origin := store.ProducedSource{Profile: "owned-produced-source-v1", File: base.Plan.Source.File, ProjectionID: secure.NewID(), ProjectionHash: secure.Digest([]byte("completed producer intent")), Producer: store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: input.ID, Version: input.Version, Hash: input.Hash, Publisher: secure.NewID(), Producer: actor}}
	output := store.ProcessingOutputBinding{Profile: "producer-processing-output-policy-v1", PolicyID: base.Plan.Policy.ID, Version: base.Plan.Policy.Version, Hash: base.Plan.Policy.Hash, Publisher: secure.NewID(), Producer: actor}
	got, err := composedProducerProjectionReview(base, row, rules, now, &output, actor, &origin)
	if err != nil || got.Plan.Schema != 4 || got.Plan.Profile != ComposedProducerProjectionProfile || got.Plan.SourceOrigin == nil || *got.Plan.SourceOrigin != origin || *got.Plan.OutputBinding != output {
		t.Fatal("separately reviewed composition lost exact input or output producer binding", err)
	}
	d := ProjectionDefinition{Schema: 4, Plan: got.Plan, Slots: []string{secure.NewID(), secure.NewID(), secure.NewID()}, Workflow: &store.ProcessingWorkflowBinding{WorkflowID: secure.NewID(), Version: 1, Hash: secure.Digest([]byte("separately approved task")), RunID: secure.NewID(), StepID: "project"}}
	wire, hash, _ := canonical(d)
	r := &store.RecordProjection{ID: secure.NewID(), SourceID: origin.File.ID, Definition: wire, Hash: hash}
	if _, err := decodeProjection(r); err != nil {
		t.Fatal("composed durable definition refused", err)
	}
	d.Plan.SourceOrigin.ProjectionHash = secure.Digest([]byte("substituted producing intent"))
	r.Definition, _, _ = canonical(d)
	if _, err := decodeProjection(r); err == nil {
		t.Fatal("source origin changed under original approval hash")
	}
	d.Plan.SourceOrigin.ProjectionHash = origin.ProjectionHash
	if _, err := producerProjectionReview(base, row, rules, now, &output, actor); err == nil {
		t.Fatal("old producer profile acquired composed-source authority")
	}
	if _, err := composedProducerProjectionReview(base, row, rules, now, &output, actor, nil); err == nil {
		t.Fatal("composition without immutable lineage")
	}
	for _, mutate := range []func(*store.ProducedSource){
		func(s *store.ProducedSource) { s.File.EventID = secure.NewID() },
		func(s *store.ProducedSource) { s.File.ID = secure.NewID() },
		func(s *store.ProducedSource) { s.File.SHA256 = secure.Digest([]byte("other bytes")) },
		func(s *store.ProducedSource) { s.ProjectionID = "" },
		func(s *store.ProducedSource) { s.Producer.PolicyID = secure.NewID() },
		func(s *store.ProducedSource) { s.Producer.Producer.Actor = secure.NewID() },
		func(s *store.ProducedSource) { s.Producer.Producer.AuthorityRevision++ },
		func(s *store.ProducedSource) { s.Producer.Producer.RootPolicyDigest = secure.Digest([]byte("/other")) },
	} {
		changed := origin
		mutate(&changed)
		if _, err := composedProducerProjectionReview(base, row, rules, now, &output, actor, &changed); err == nil {
			t.Fatal("substituted source provenance accepted")
		}
	}
	base.PreviousPolicy.State = "output_revoked"
	if _, err := composedProducerProjectionReview(base, row, rules, now, &output, actor, &origin); err == nil {
		t.Fatal("revoked generated source accepted")
	}
	origin.Producer.Publisher = secure.NewID()
	if got.Plan.SourceOrigin.Producer.Publisher == origin.Producer.Publisher {
		t.Fatal("caller changed reviewed source provenance")
	}
	if validProjectionProfile(ProjectionPlan{Schema: 3, Profile: ProducerProjectionProfile, Context: got.Plan.Context, OutputBinding: got.Plan.OutputBinding, SourceOrigin: got.Plan.SourceOrigin}) {
		t.Fatal("old plan accepts additive composition authority")
	}
}
