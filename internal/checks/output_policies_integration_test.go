//go:build integration

package checks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func outputProducerFixture(t *testing.T) (*fixture, *Service, store.Scope, store.AccountCommand, store.Configuration) {
	t.Helper()
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	registered, err := s.Register(f.ctx, f.scope, "output-registry-default-input", PolicyRequest{Definition: testPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var input store.Configuration
	if json.Unmarshal(registered.Resource, &input) != nil {
		t.Fatal("default input")
	}
	mode := uint32(0777)
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "output-producer-root", store.PathCommand{Operation: "mkdir", Path: "/processor", Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	account := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Bound output producer", Root: "/processor", Permissions: []string{"read", "write", "check_run", "workflow_execute"}}}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, f.scope, "output-producer-account", account); err != nil {
		t.Fatal(err)
	}
	producer := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: account.CredentialHash}
	return f, s, producer, account, input
}
func registerOutputFixture(t *testing.T, f *fixture, s *Service, account store.AccountCommand, input store.Configuration) (OutputPolicyRequest, OutputPolicyRecord) {
	t.Helper()
	rules, err := NormalizeRecordProjection(testPolicy(t), RecordProjection{Schema: 1, Kind: "record_projection", SourcePolicyHash: input.Hash, OutputKind: "json_records", Columns: []ProjectionColumn{{Source: "account", Target: "account"}, {Source: "amount", Target: "total"}, {Source: "day", Target: "day"}}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := projectionOutputPolicy(testPolicy(t), rules)
	if err != nil {
		t.Fatal(err)
	}
	request := OutputPolicyRequest{Producer: account.ID, Definition: output}
	result, err := s.RegisterOutputPolicy(f.ctx, f.scope, "register-output-contract", request)
	if err != nil {
		t.Fatal(err)
	}
	var record OutputPolicyRecord
	if json.Unmarshal(result.Resource, &record) != nil || record.Policy.State != "output_active" || record.Usage != "producer-workflow-output-contract" || record.IngressChanged {
		t.Fatal("output registration receipt")
	}
	return request, record
}
func TestProcessingOutputPolicyActualRegistrationPreservesRepeatedCSVIngress(t *testing.T) {
	f, s, producer, account, input := outputProducerFixture(t)
	request, record := registerOutputFixture(t, f, s, account, input)
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.ID != input.ID || current.Version != input.Version || current.Hash != input.Hash || current.State != "active" {
		t.Fatal("output registration replaced the default ingress policy", err)
	}
	if _, err = s.RegisterOutputPolicy(f.ctx, producer, "cannot-administer-output", request); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("output registration granted administration", err)
	}
	for i := 0; i < 2; i++ {
		key := "repeated-csv-" + string(rune('a'+i))
		file, _, err := s.Custody.AcceptAt(f.ctx, producer, key, int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/" + key + ".csv"})
		if err != nil {
			t.Fatal("later CSV input no longer accepted", err)
		}
		if _, err = s.Run(f.ctx, producer, file.ID, key+"-check"); err != nil {
			t.Fatal("later CSV input checked against output format", err)
		}
	}
	view, err := s.OutputPolicy(f.ctx, producer, record.Policy.ID, 1)
	if err != nil || !view.ProducerCurrent || view.Binding.Producer.Actor != account.ID {
		t.Fatal("bound producer cannot inspect its contract", err)
	}
	replay, err := s.RegisterOutputPolicy(f.ctx, f.scope, "register-output-contract", request)
	if err != nil || !replay.Replayed || !sameProcessingReceipt(replay.Resource, mustOutputJSON(t, record)) {
		t.Fatal("output registration replay changed original contract", err)
	}
}

func TestProcessingOutputPolicyActualRegistryAloneDoesNotConfigureIngress(t *testing.T) {
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	identity, err := s.Custody.DB.Identity(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterOutputPolicy(f.ctx, f.scope, "output-only-registry", OutputPolicyRequest{Producer: identity.Actor, Definition: testPolicy(t)}); err != nil {
		t.Fatal(err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current != nil {
		t.Fatal("output contract configured an ingress policy", err)
	}
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "output-only-ingress", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/registry-only.csv"})
	if err != nil || file.Policy != "integrity-only-v1" {
		t.Fatal("registry-only contract changed ordinary acceptance", err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var currentForExchange bool
	if err = tx.Tx.QueryRow(f.ctx, `SELECT freightctl_artifact_exchange_policy_current($1,$2,$3)`, f.scope.Tenant, f.scope.Partner, file.ID).Scan(&currentForExchange); err != nil || !currentForExchange {
		t.Fatal("output registry changed exchange ingress selection", err)
	}
}
func mustOutputJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestProcessingOutputPolicyActualVersionsAndOtherProducersCannotAlterIngress(t *testing.T) {
	f, s, producer, account, input := outputProducerFixture(t)
	request, record := registerOutputFixture(t, f, s, account, input)
	other := store.AccountCommand{Operation: "create", ID: secure.NewID(), CredentialHash: secure.Digest([]byte(secure.NewID())), Policy: &store.AccountPolicy{Label: "Other output producer", Root: "/processor", Permissions: []string{"read", "write", "check_run", "workflow_execute"}}}
	if _, err := s.Custody.DB.ChangeAccount(f.ctx, f.scope, "other-output-producer", other); err != nil {
		t.Fatal(err)
	}
	otherScope := store.Scope{Tenant: f.scope.Tenant, Partner: f.scope.Partner, TokenHash: other.CredentialHash}
	if _, err := s.OutputPolicy(f.ctx, otherScope, record.Policy.ID, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("another actor inspected private output policy", err)
	}
	request.ID = record.Policy.ID
	request.ExpectedVersion = 1
	request.Producer = other.ID
	changed, err := s.RegisterOutputPolicy(f.ctx, f.scope, "new-output-producer-version", request)
	if err != nil {
		t.Fatal(err)
	}
	var next OutputPolicyRecord
	if json.Unmarshal(changed.Resource, &next) != nil || next.Policy.Version != 2 || next.Binding.Producer.Actor != other.ID {
		t.Fatal("producer change did not require a new version")
	}
	visible, err := s.OutputPolicies(f.ctx, producer, "", 25)
	if err != nil || len(visible.Policies) != 0 {
		t.Fatal("old producer discovered another actor's new contract", err)
	}
	old, err := s.OutputPolicy(f.ctx, producer, record.Policy.ID, 1)
	if err != nil || old.Policy.State != "output_retired" {
		t.Fatal("old contract history lost", err)
	}
	// Legacy versions remain contiguous even when output families use the same
	// numeric versions. A new ingress version still follows its own existing head.
	if _, err = s.Register(f.ctx, f.scope, "default-input-version-two", PolicyRequest{ExpectedVersion: 1, Definition: testPolicy(t)}); err != nil {
		t.Fatal("output versions displaced ingress numbering", err)
	}
	current, err := s.Policy(f.ctx, f.scope)
	if err != nil || current.ID != input.ID || current.Version != 2 || current.State != "active" {
		t.Fatal("default ingress lineage changed", err)
	}
}
func TestProcessingOutputPolicyActualCredentialRevocationAndPolicyRevocationStaySeparate(t *testing.T) {
	f, s, producer, account, input := outputProducerFixture(t)
	request, record := registerOutputFixture(t, f, s, account, input)
	current, err := s.Custody.DB.Account(f.ctx, f.scope, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Custody.DB.ChangeAccount(f.ctx, f.scope, "revoke-output-producer", store.AccountCommand{Operation: "revoke", ID: account.ID, ExpectedRevision: current.Revision}); err != nil {
		t.Fatal(err)
	}
	admin, err := s.OutputPolicy(f.ctx, f.scope, record.Policy.ID, 1)
	if err != nil || admin.ProducerCurrent {
		t.Fatal("revoked producer still current", err)
	}
	if _, err = s.OutputPolicy(f.ctx, producer, record.Policy.ID, 1); err == nil {
		t.Fatal("revoked producer retained contract access")
	}
	if _, err = s.RevokeOutputPolicy(f.ctx, f.scope, record.Policy.ID, 1, "revoke-output-contract", PolicyDecision{Hash: record.Policy.Hash, Version: 1, Revision: 1}); err != nil {
		t.Fatal(err)
	}
	admin, err = s.OutputPolicy(f.ctx, f.scope, record.Policy.ID, 1)
	if err != nil || admin.Policy.State != "output_revoked" {
		t.Fatal("output contract not revoked", err)
	}
	replay, err := s.RegisterOutputPolicy(f.ctx, f.scope, "register-output-contract", request)
	if err != nil || !replay.Replayed {
		t.Fatal("revocation erased original registration", err)
	}
	defaultPolicy, err := s.Policy(f.ctx, f.scope)
	if err != nil || defaultPolicy.State != "active" || defaultPolicy.Hash != input.Hash {
		t.Fatal("output revocation changed ingress", err)
	}
}
func TestProcessingOutputPolicyActualSQLRejectsMissingBindingDefaultConversionAndProducerWrite(t *testing.T) {
	f, s, producer, account, input := outputProducerFixture(t)
	_, record := registerOutputFixture(t, f, s, account, input)
	tx, err := s.Custody.DB.BeginApproval(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	c := *record.Policy
	c.ID = secure.NewID()
	err = tx.SaveIntakePolicy(f.ctx, &c, 0)
	if err == nil {
		err = tx.Tx.Commit(f.ctx)
	} else {
		tx.Tx.Rollback(f.ctx)
	}
	if err == nil {
		t.Fatal("unbound output policy committed")
	}
	tx, err = s.Custody.DB.BeginApproval(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	c = input
	c.State = "output_retired"
	c.Revision++
	err = tx.SaveIntakePolicy(f.ctx, &c, input.Revision)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("default ingress converted into output lane")
	}
	tx, err = s.Custody.DB.BeginApproval(f.ctx, producer)
	if err != nil {
		t.Fatal(err)
	}
	c = *record.Policy
	c.ID = secure.NewID()
	err = tx.SaveIntakePolicy(f.ctx, &c, 0)
	tx.Tx.Rollback(f.ctx)
	if err == nil {
		t.Fatal("producer forged output administration through SQL")
	}
	unchanged, err := s.Policy(f.ctx, f.scope)
	if err != nil || unchanged.State != "active" || unchanged.Version != input.Version || unchanged.Hash != input.Hash {
		t.Fatal("failed output mutation changed ingress", err)
	}
}
