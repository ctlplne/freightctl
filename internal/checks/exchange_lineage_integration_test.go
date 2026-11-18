//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

type ProjectionExchangeFixture struct {
	lab            *fixture
	checker        *Service
	Custody        *custody.Service
	Sender         store.Scope
	Recipient      store.Scope
	SenderToken    string
	RecipientToken string
	Offer          store.ArtifactExchange
	Output         *store.File
	Lineage        store.ExchangeProjectionLineage
}

// PrepareProjectionExchange shares the approved, separately released output
// between the service regression and the production HTTP/browser test.
func PrepareProjectionExchange(t *testing.T) ProjectionExchangeFixture {
	t.Helper()
	f, s, config, _, source := producerProjectionFixture(t)
	service := s.Custody
	service.Exchanges = custody.ExchangeSettings{MaxLifetime: time.Hour, MaxSenders: 4, MaxOpenViews: 4, MaxEndpoints: 4}
	run := processingWorkflowRun(t, f, &config, source, "lineage-run")
	worked, err := f.wf.Work(f.ctx, f.scope, run.ID, "lineage-work")
	if err != nil || worked.Processing == nil || worked.Processing.State != "completed" {
		t.Fatal("deterministic projection did not complete", err)
	}
	outputID := worked.Processing.FileID
	if _, err = s.Run(f.ctx, f.scope, outputID, "lineage-output-check"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, outputID, "lineage-output-release", releaseDecision(getCheck(t, s, f, outputID))); err != nil {
		t.Fatal(err)
	}
	output, reader, err := service.Download(f.ctx, f.scope, outputID)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	recipientToken := filepath.Join(t.TempDir(), "recipient.token")
	if err = secure.WriteToken(recipientToken); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(recipientToken, 64)
	if err != nil {
		t.Fatal(err)
	}
	receiver := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	if _, err = service.DB.ChangeAccount(f.ctx, f.scope, "lineage-receiver", store.AccountCommand{
		Operation: "create", ID: secure.NewID(), CredentialHash: receiver.TokenHash,
		Policy: &store.AccountPolicy{Label: "Independent lineage recipient", Root: "/", Permissions: []string{"read", "list"}},
	}); err != nil {
		t.Fatal(err)
	}
	participant := func(scope store.Scope) store.ExchangeParticipant {
		t.Helper()
		identity, err := service.DB.Identity(f.ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		return store.ExchangeParticipant{Tenant: scope.Tenant, Partner: scope.Partner, Actor: identity.Actor, AuthorityRevision: identity.AuthorityRevision, RootPolicyDigest: identity.RootPolicyDigest}
	}
	limits, _, err := service.ExchangeLimits()
	if err != nil {
		t.Fatal(err)
	}
	registered, err := service.DB.RegisterExchangeEndpoint(f.ctx, f.scope, "lineage-endpoint", store.ExchangeEndpointCommand{
		Operation: "create", ID: secure.NewID(), Definition: &store.ExchangeEndpointDefinition{
			Schema: 1, Profile: "custody-https-poll-v1", Recipient: participant(receiver), Senders: []store.ExchangeParticipant{participant(f.scope)},
		},
	}, limits, 4)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := registered.Endpoint
	offered, err := service.OfferExchange(f.ctx, f.scope, "lineage-offer", store.ExchangeRequest{
		Schema: 1, Artifact: store.ExchangeArtifact{ID: output.ID, Size: output.Size, SHA256: output.SHA256, Policy: output.Policy},
		Endpoint:  store.ExchangeEndpointReference{ID: endpoint.ID, Revision: endpoint.Revision, Hash: endpoint.Hash},
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond), Receipt: "availability-only-v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := service.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	lineage := store.ExchangeProjectionLineage{
		Source:      store.ExchangeArtifact{ID: source.ID, Size: source.Size, SHA256: source.SHA256, Policy: source.Policy},
		SourceEvent: source.EventID,
	}
	err = tx.Tx.QueryRow(f.ctx, `SELECT r.projection_id::text,r.definition_hash,e.event_id::text,e.happened_at FROM record_projections r JOIN events e ON e.event_id=r.changed_event_id AND e.kind='RecordProjectionChanged' WHERE r.new_file_id=$1 AND r.source_file_id=$2 AND r.state='completed'`, outputID, source.ID).Scan(&lineage.ProjectionID, &lineage.DefinitionHash, &lineage.CompletedEvent, &lineage.CompletedAt)
	if err != nil {
		t.Fatal("exact completed processing event unavailable", err)
	}
	lineage.CompletedAt = lineage.CompletedAt.UTC()
	return ProjectionExchangeFixture{lab: f, checker: s, Custody: service, Sender: f.scope, Recipient: receiver, SenderToken: f.tokenPath, RecipientToken: recipientToken, Offer: offered.Exchange, Output: output, Lineage: lineage}
}

func (f ProjectionExchangeFixture) ReleaseSource(t *testing.T) {
	t.Helper()
	id := f.Lineage.Source.ID
	if _, err := f.checker.Release(f.lab.ctx, f.Sender, id, "lineage-source-release", releaseDecision(getCheck(t, f.checker, f.lab, id))); err != nil {
		t.Fatal(err)
	}
	entry, err := f.Custody.StatPath(f.lab.ctx, f.Sender, "/checked.csv")
	if err != nil || entry.FileID != id {
		t.Fatal("source release did not publish the exact input", err)
	}
	mode := uint32(0600)
	if _, err = f.Custody.PathCommand(f.lab.ctx, f.Sender, "lineage-source-owner-only", store.PathCommand{
		Operation: "setstat", Path: entry.Path, ExpectedRevision: &entry.Revision, Mode: &mode,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeTraceActualProjectionLineageRequiresCurrentSourceRead(t *testing.T) {
	f := PrepareProjectionExchange(t)
	ctx, service, source := f.lab.ctx, f.Custody, f.Lineage.Source
	request := store.ExchangeTraceRequest{ID: f.Offer.ID, Direction: "outgoing", Profile: store.ExchangeEvidenceV2}
	read := func(scope store.Scope, request store.ExchangeTraceRequest, disclose bool) json.RawMessage {
		t.Helper()
		trace, err := service.TraceExchange(ctx, scope, request)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(trace)
		if err != nil {
			t.Fatal(err)
		}
		var evidence map[string]json.RawMessage
		if err = json.Unmarshal(wire, &evidence); err != nil {
			t.Fatal(err)
		}
		lineage := evidence["record_projection"]
		if (lineage != nil) != disclose {
			t.Fatal("projection evidence differs from current source authority")
		}
		if !disclose && (bytes.Contains(wire, []byte(source.ID)) || bytes.Contains(wire, []byte(source.SHA256))) {
			t.Fatal("withheld evidence leaked source identity")
		}
		if trace.Profile != request.Profile || trace.Artifact == nil || *trace.Artifact != f.Offer.Request.Artifact || len(trace.Events) != 2 || trace.Events[0].ID != f.Output.EventID || trace.StorageVerification != "not-checked" || trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
			t.Fatal("trace changed custody or receiver observations")
		}
		return lineage
	}
	read(f.Sender, request, false)
	f.ReleaseSource(t)
	lineage := read(f.Sender, request, true)
	legacy, err := service.TraceExchange(ctx, f.Sender, store.ExchangeTraceRequest{ID: request.ID, Direction: request.Direction})
	if err != nil || legacy.Profile != store.ExchangeEvidenceV1 || legacy.Projection != nil {
		t.Fatal("legacy evidence profile changed", err)
	}
	var observed store.ExchangeProjectionLineage
	if err = json.Unmarshal(lineage, &observed); err != nil {
		t.Fatal(err)
	}
	if observed != f.Lineage {
		t.Fatal("projected evidence does not match the exact accepted input and completed processing journal")
	}
	if bytes.Contains(lineage, []byte("checked.csv")) || bytes.Contains(lineage, []byte("account")) || bytes.Contains(lineage, []byte("report")) || bytes.Contains(lineage, []byte(service.Disk.Identity())) {
		t.Fatal("lineage exposed private rules, path, storage or payload")
	}
	var manifest bytes.Buffer
	prepared, err := service.PreparePortableExchangeTrace(ctx, f.Sender, store.ExchangeTraceExportSelection{ExchangeTraceRequest: request, RequestHash: f.Offer.RequestHash}, &manifest)
	if err != nil || prepared.SHA256 != secure.Digest(manifest.Bytes()) || !bytes.Contains(manifest.Bytes(), lineage) {
		t.Fatal("export lost the authorized lineage", err)
	}
	if _, err = service.TraceExchange(ctx, f.Recipient, request); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("recipient could inspect original sender evidence", err)
	}
	request.Direction = "incoming"
	read(f.Recipient, request, false)
}
