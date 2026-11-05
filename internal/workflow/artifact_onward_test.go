package workflow

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestOnwardBrowserFixtureMatchesExactGoReviewAndReceipt(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/artifact-onward.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Binding   onwardBinding `json:"binding"`
		Review    OnwardReview  `json:"review"`
		Result    Result        `json:"result"`
		Canonical string        `json:"result_canonical"`
	}
	if json.Unmarshal(raw, &fixture) != nil {
		t.Fatal("invalid fixture")
	}
	hash, err := onwardBindingHash(fixture.Binding)
	if err != nil || hash != fixture.Review.ReviewHash {
		t.Fatal("browser and server review fingerprints differ", err)
	}
	var receipt OnwardRunReceipt
	if json.Unmarshal(fixture.Result.Resource, &receipt) != nil || receipt.ReviewHash != hash || receipt.Profile != OnwardProfile || receipt.WorkflowRevision != fixture.Binding.WorkflowRevision {
		t.Fatal("typed reviewed receipt differs")
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(Result{Resource: encoded, Replayed: false})
	if err != nil || string(actual) != fixture.Canonical {
		t.Fatal("browser receipt fixture differs from actual Go shape", err)
	}
}

func onwardBindingFixture() onwardBinding {
	id := func(n string) string { return n + "1111111-1111-4111-8111-111111111111" }
	return onwardBinding{Request: OnwardRequest{Schema: 1, Profile: OnwardProfile, Workflow: Reference{ID: id("1"), Version: 1, Hash: strings.Repeat("a", 64)}, Artifact: store.ExchangeArtifact{ID: id("2"), Size: 3, SHA256: strings.Repeat("b", 64), Policy: "integrity-only-v1"}}, Tenant: id("3"), Partner: id("4"), Actor: id("5"), Authority: 2, RootDigest: strings.Repeat("c", 64), WorkflowRevision: 2, StorageDigest: strings.Repeat("d", 64)}
}
func TestOnwardReviewBindsEveryAuthorityWorkflowArtifactAndStorageRevision(t *testing.T) {
	base := onwardBindingFixture()
	hash, err := onwardBindingHash(base)
	if err != nil || len(hash) != 64 {
		t.Fatal("valid review binding refused", err)
	}
	changes := []func(*onwardBinding){func(b *onwardBinding) { b.Tenant = "99999999-1111-4111-8111-111111111111" }, func(b *onwardBinding) { b.Partner = b.Tenant }, func(b *onwardBinding) { b.Actor = b.Tenant }, func(b *onwardBinding) { b.Authority++ }, func(b *onwardBinding) { b.RootDigest = strings.Repeat("e", 64) }, func(b *onwardBinding) { b.WorkflowRevision++ }, func(b *onwardBinding) { b.StorageDigest = strings.Repeat("e", 64) }, func(b *onwardBinding) { b.Request.Workflow.Version++ }, func(b *onwardBinding) { b.Request.Workflow.Hash = strings.Repeat("e", 64) }, func(b *onwardBinding) { b.Request.Artifact.ID = b.Tenant }, func(b *onwardBinding) { b.Request.Artifact.Size++ }, func(b *onwardBinding) { b.Request.Artifact.SHA256 = strings.Repeat("e", 64) }, func(b *onwardBinding) { b.Request.Artifact.Policy = "intake-csv-v1:" + strings.Repeat("e", 64) }}
	for _, change := range changes {
		other := base
		change(&other)
		changed, err := onwardBindingHash(other)
		if err != nil || changed == hash {
			t.Fatal("review lost a consequential binding", err)
		}
	}
}
func TestOnwardControlContractRefusesUnsupportedMeaningAndCapacity(t *testing.T) {
	base := onwardBindingFixture().Request
	if validateOnwardRequest(base, 3) != nil {
		t.Fatal("exact configured maximum refused")
	}
	for _, change := range []func(*OnwardRequest){func(r *OnwardRequest) { r.Schema = 2 }, func(r *OnwardRequest) { r.Profile = "automatic-forward" }, func(r *OnwardRequest) { r.Workflow.Version = 0 }, func(r *OnwardRequest) { r.Artifact.Size = 4 }, func(r *OnwardRequest) { r.Artifact.SHA256 = "unknown" }, func(r *OnwardRequest) { r.Artifact.Policy = "scanner-waived" }} {
		request := base
		change(&request)
		if validateOnwardRequest(request, 3) == nil {
			t.Fatal("unqualified or over-capacity onward request accepted")
		}
	}
}
