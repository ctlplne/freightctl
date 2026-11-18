//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestExchangeTraceActualProjectionLineageRequiresCurrentSourceRead(t *testing.T) {
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
	receiver := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: secure.Digest([]byte(secure.NewID()))}
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
	request := store.ExchangeTraceRequest{ID: offered.Exchange.ID, Direction: "outgoing"}
	request.Profile = store.ExchangeEvidenceV2
	read := func(scope store.Scope, request store.ExchangeTraceRequest, disclose bool) json.RawMessage {
		t.Helper()
		trace, err := service.TraceExchange(f.ctx, scope, request)
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
		if trace.Profile != request.Profile || trace.Artifact == nil || trace.Artifact.ID != outputID || len(trace.Events) != 2 || trace.Events[0].ID != output.EventID || trace.StorageVerification != "not-checked" || trace.Retrieval != "unknown" || trace.ReceiverPersistence != "unknown" || trace.BusinessProcessing != "unknown" {
			t.Fatal("trace changed custody or receiver observations")
		}
		return lineage
	}
	read(f.scope, request, false)
	if _, err = s.Release(f.ctx, f.scope, source.ID, "lineage-source-release", releaseDecision(getCheck(t, s, f, source.ID))); err != nil {
		t.Fatal(err)
	}
	lineage := read(f.scope, request, true)
	legacy, err := service.TraceExchange(f.ctx, f.scope, store.ExchangeTraceRequest{ID: request.ID, Direction: request.Direction})
	if err != nil || legacy.Profile != store.ExchangeEvidenceV1 || legacy.Projection != nil {
		t.Fatal("legacy evidence profile changed", err)
	}
	var observed store.ExchangeProjectionLineage
	if err = json.Unmarshal(lineage, &observed); err != nil {
		t.Fatal(err)
	}
	tx, err := service.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var projectionID, definitionHash, completionID string
	var completedAt time.Time
	err = tx.Tx.QueryRow(f.ctx, `SELECT r.projection_id::text,r.definition_hash,e.event_id::text,e.happened_at FROM record_projections r JOIN events e ON e.event_id=r.changed_event_id AND e.kind='RecordProjectionChanged' WHERE r.new_file_id=$1 AND r.source_file_id=$2 AND r.state='completed'`, outputID, source.ID).Scan(&projectionID, &definitionHash, &completionID, &completedAt)
	if err != nil || observed.ProjectionID != projectionID || observed.DefinitionHash != definitionHash || observed.Source != (store.ExchangeArtifact{ID: source.ID, Size: source.Size, SHA256: source.SHA256, Policy: source.Policy}) || observed.SourceEvent != source.EventID || observed.CompletedEvent != completionID || !observed.CompletedAt.Equal(completedAt) {
		t.Fatal("projected evidence does not match the exact accepted input and completed processing journal", err)
	}
	if bytes.Contains(lineage, []byte("checked.csv")) || bytes.Contains(lineage, []byte("account")) || bytes.Contains(lineage, []byte("report")) || bytes.Contains(lineage, []byte(service.Disk.Identity())) {
		t.Fatal("lineage exposed private rules, path, storage or payload")
	}
	var manifest bytes.Buffer
	prepared, err := service.PreparePortableExchangeTrace(f.ctx, f.scope, store.ExchangeTraceExportSelection{ExchangeTraceRequest: request, RequestHash: offered.Exchange.RequestHash}, &manifest)
	if err != nil || prepared.SHA256 != secure.Digest(manifest.Bytes()) || !bytes.Contains(manifest.Bytes(), lineage) {
		t.Fatal("export lost the authorized lineage", err)
	}
	if _, err = service.TraceExchange(f.ctx, receiver, request); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("recipient could inspect original sender evidence", err)
	}
	request.Direction = "incoming"
	read(receiver, request, false)
}
