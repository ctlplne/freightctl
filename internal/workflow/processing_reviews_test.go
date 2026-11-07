package workflow

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProcessingReviewPinsIndependentParticipantsAndExactTypedDraft(t *testing.T) {
	d, err := Normalize(processingWorkflow(t))
	if err != nil {
		t.Fatal(err)
	}
	wire, hash, _ := digest(d)
	cfg := &store.Configuration{ID: secure.NewID(), Version: 1, Definition: wire, Hash: hash, State: "draft", Revision: 1}
	author := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 7, RootDigest: secure.Digest([]byte("/processor"))}
	reviewer := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 4, RootDigest: secure.Digest([]byte("/"))}
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	review, err := processingReviewDefinition(cfg, author, reviewer, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if review.Workflow.Hash != hash || review.WorkflowRevision != 1 || review.Author != author || review.Reviewer != reviewer || review.Profile != "independent-processing-workflow-review-v1" {
		t.Fatal("lost immutable approval binding")
	}
	cfg.Definition[0] = 'x'
	var copied Definition
	if Decode(review.Definition, &copied) != nil {
		t.Fatal("review aliases caller-owned definition")
	}
	b, _ := json.Marshal(review)
	for _, secret := range []string{"storage_id", "token", "private_key", "source_file_id"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("review acquired private runtime/payload authority")
		}
	}
}

func TestProcessingReviewRefusesSelfApprovalStaleMeaningAndUnboundedLifetime(t *testing.T) {
	d, _ := Normalize(processingWorkflow(t))
	wire, hash, _ := digest(d)
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	base := store.Configuration{ID: secure.NewID(), Version: 1, Definition: wire, Hash: hash, State: "draft", Revision: 1}
	a := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 7, RootDigest: secure.Digest([]byte("/processor"))}
	r := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 4, RootDigest: secure.Digest([]byte("/"))}
	for _, mutate := range []func(*store.Configuration, *store.ProcessingReviewParticipant, *store.ProcessingReviewParticipant, *time.Time){
		func(_ *store.Configuration, a, r *store.ProcessingReviewParticipant, _ *time.Time) { r.Actor = a.Actor },
		func(c *store.Configuration, _, _ *store.ProcessingReviewParticipant, _ *time.Time) {
			c.Hash = strings.Repeat("f", 64)
		},
		func(c *store.Configuration, _, _ *store.ProcessingReviewParticipant, _ *time.Time) {
			c.State = "approved"
		},
		func(_ *store.Configuration, a, _ *store.ProcessingReviewParticipant, _ *time.Time) { a.Authority = 0 },
		func(_ *store.Configuration, _, r *store.ProcessingReviewParticipant, _ *time.Time) { r.RootDigest = "" },
		func(_ *store.Configuration, _, _ *store.ProcessingReviewParticipant, e *time.Time) { *e = now },
		func(_ *store.Configuration, _, _ *store.ProcessingReviewParticipant, e *time.Time) {
			*e = now.Add(31 * 24 * time.Hour)
		},
	} {
		c, author, reviewer, until := base, a, r, now.Add(time.Hour)
		mutate(&c, &author, &reviewer, &until)
		if _, err := processingReviewDefinition(&c, author, reviewer, until, now); err == nil {
			t.Fatal("unsafe independent approval accepted")
		}
	}
	legacy := base
	legacy.Definition = json.RawMessage(`{"schema_version":1,"name":"legacy","steps":[]}`)
	legacy.Hash = secure.Digest(legacy.Definition)
	if _, err := processingReviewDefinition(&legacy, a, r, now.Add(time.Hour), now); err == nil {
		t.Fatal("review granted legacy delivery authority")
	}
}

func TestProcessingReviewNormalizesJSONBOrderAndRefusesChangedDisclosure(t *testing.T) {
	d, _ := Normalize(processingWorkflow(t))
	wire, hash, _ := digest(d)
	c := &store.Configuration{ID: secure.NewID(), Version: 1, Hash: hash, State: "draft", Revision: 1, Definition: wire}
	now := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	a := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 7, RootDigest: secure.Digest([]byte("/processor"))}
	r := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 4, RootDigest: secure.Digest([]byte("/"))}
	definition, err := processingReviewDefinition(c, a, r, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	_, reviewHash, _ := digest(definition)
	var unordered map[string]any
	if json.Unmarshal(definition.Definition, &unordered) != nil {
		t.Fatal("fixture")
	}
	definition.Definition, _ = json.Marshal(unordered)
	row := &store.ProcessingReview{ID: secure.NewID(), Definition: definition, Hash: reviewHash, State: "pending", Revision: 1, CreatedAt: now}
	if err = normalizeProcessingReview(row); err != nil {
		t.Fatal("JSONB ordering changed approved meaning", err)
	}
	row.Definition.Definition = json.RawMessage(strings.Replace(string(row.Definition.Definition), "Map reviewed settlement records", "A changed reason", 1))
	if normalizeProcessingReview(row) == nil {
		t.Fatal("changed disclosure kept original review hash")
	}
}

func TestProcessingReviewPrivateMetadataRequiresExactParticipantRootAndAuthority(t *testing.T) {
	a := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 7, RootDigest: secure.Digest([]byte("/processor"))}
	r := store.ProcessingReviewParticipant{Actor: secure.NewID(), Authority: 4, RootDigest: secure.Digest([]byte("/"))}
	row := &store.ProcessingReview{Definition: store.ProcessingReviewDefinition{Author: a, Reviewer: r}}
	owner := &store.Transaction{Actor: a.Actor, AuthorityRevision: a.Authority, Root: "/processor", Permissions: []string{"workflow_manage"}}
	reviewer := &store.Transaction{Actor: r.Actor, AuthorityRevision: r.Authority, Root: "/", Permissions: []string{"inspect", "workflow_approve"}}
	if checkReviewParticipant(owner, row) != nil || checkReviewParticipant(reviewer, row) != nil {
		t.Fatal("named participants denied")
	}
	for _, mutate := range []func(*store.Transaction){func(t *store.Transaction) { t.Actor = secure.NewID() }, func(t *store.Transaction) { t.Root = "/elsewhere" }, func(t *store.Transaction) { t.AuthorityRevision++ }, func(t *store.Transaction) { t.Permissions = []string{"workflow_approve"} }} {
		changed := *reviewer
		mutate(&changed)
		if checkReviewParticipant(&changed, row) == nil {
			t.Fatal("private review survived a scope/authority change")
		}
	}
}

func TestProcessingReviewCommandReceiptContainsReferencesRatherThanDuplicatePrivateDefinitions(t *testing.T) {
	r := &store.ProcessingReview{ID: secure.NewID(), Hash: strings.Repeat("a", 64), State: "adopted", Revision: 3, AdoptedRevision: 3, Definition: store.ProcessingReviewDefinition{Definition: json.RawMessage(`{"private_reason":"do not copy this into every receipt"}`), Author: store.ProcessingReviewParticipant{Actor: secure.NewID()}, Reviewer: store.ProcessingReviewParticipant{Actor: secure.NewID()}, Workflow: store.ProcessingReviewWorkflow{ID: secure.NewID(), Version: 1, Hash: strings.Repeat("b", 64)}, ExpiresAt: time.Date(2026, 11, 6, 1, 0, 0, 0, time.UTC)}}
	b, err := json.Marshal(processingReviewSummary(r))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2048 || strings.Contains(string(b), "private_reason") || strings.Contains(string(b), `"definition":`) {
		t.Fatal("compact receipt copied private definition")
	}
	var summary store.ProcessingReviewSummary
	if json.Unmarshal(b, &summary) != nil || summary.ID != r.ID || summary.Hash != r.Hash || summary.Revision != r.Revision || summary.AdoptedRevision != r.AdoptedRevision || summary.WorkflowID != r.Definition.Workflow.ID {
		t.Fatal("compact receipt lost exact original binding")
	}
}

func TestProcessingReviewBrowserGoldenMatchesGoCanonicalDefinition(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/processing-review.json")
	if err != nil {
		t.Fatal(err)
	}
	var r store.ProcessingReview
	if Decode(raw, &r) != nil {
		t.Fatal("review fixture")
	}
	if err = normalizeProcessingReview(&r); err != nil {
		t.Fatal("Go/Python/browser canonical review meaning differs", err)
	}
}
