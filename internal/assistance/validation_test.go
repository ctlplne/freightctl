package assistance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
)

func TestRedactionPrecedesPersistenceAndDisclosure(t *testing.T) {
	cases := []struct{ Input, Absent string }{
		{"password=short-value then send to receiver", "short-value"},
		{"Bearer " + strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{"use https://user:secret@example.invalid/path", "secret"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nshort fragment", "short fragment"},
		{"send sensitive.csv to /private/partner", "sensitive.csv"},
	}
	for _, c := range cases {
		output, err := redact(c.Input, []string{"sensitive.csv", "/private/partner"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output, c.Absent) {
			t.Fatal("recognized private material retained", output)
		}
	}
	if _, err := redact(strings.Repeat("x", 4097), nil); err == nil {
		t.Fatal("operator text bound ignored")
	}
}
func TestProposalCannotGrantAuthorityOrAddRecipients(t *testing.T) {
	contextData, _, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1", "d2"}})
	j := &store.AIJob{Kind: "propose", Context: contextData, Bindings: json.RawMessage(`{}`)}
	for _, output := range []string{
		`{"status":"ready","order":["d1","external"],"missing":[]}`,
		`{"status":"ready","order":["d1","d1"],"missing":[]}`,
		`{"status":"ready","order":["d1","d2"],"missing":[],"approved":true}`,
		`{"status":"ready","order":["d1","d2"],"missing":[],"tools":["execute"]}`,
		`{"status":"ready","status":"unsupported","order":[],"missing":["supported_task"]}`,
		`{"status":"needs_input","order":["d1"],"missing":["filename"]}`,
	} {
		if _, err := validateOutput(j, output); err == nil {
			t.Fatal("unsafe output accepted", output)
		}
	}
	if _, err := validateOutput(j, `{"status":"ready","order":["d2","d1"],"missing":[]}`); err != nil {
		t.Fatal(err)
	}
}
func TestDiagnosisMustMatchExactSupportedEvidence(t *testing.T) {
	c := Context{Schema: 1, Kind: "diagnose", Facts: []Fact{{Alias: "e1", Code: "uncertain_delivery"}}, Supported: []Finding{{Code: "uncertain_delivery", Evidence: []string{"e1"}, NextCheck: "read_only_reconcile"}}}
	b := Bindings{Evidence: map[string][]Citation{"e1": {{EventID: "recorded-event", Kind: "DeliveryTransitioned", ResourceID: "recorded-delivery"}}}}
	contextData, _, _ := canonical(c)
	bindings, _, _ := canonical(b)
	j := &store.AIJob{Kind: "diagnose", Context: contextData, Bindings: bindings}
	for _, output := range []string{
		`{"code":"transport_complete","evidence":["e1"],"next_check":"obtain_business_receipt"}`,
		`{"code":"uncertain_delivery","evidence":["forged"],"next_check":"read_only_reconcile"}`,
		`{"code":"uncertain_delivery","evidence":["e1"],"next_check":"resend"}`,
		`{"code":"uncertain_delivery","evidence":["e1","e1"],"next_check":"read_only_reconcile"}`,
	} {
		if _, err := validateOutput(j, output); err == nil {
			t.Fatal("unsupported diagnosis accepted", output)
		}
	}
	result, err := validateOutput(j, `{"code":"uncertain_delivery","evidence":["e1"],"next_check":"read_only_reconcile"}`)
	if err != nil || len(result.Citations) != 1 || result.Citations[0].EventID != "recorded-event" {
		t.Fatal(result, err)
	}
}
func FuzzUntrustedModelOutput(f *testing.F) {
	f.Add(`{"status":"ready","order":["d1"],"missing":[]}`)
	f.Add(`{"approved":true,"destination":"https://outside.invalid"}`)
	f.Fuzz(func(t *testing.T, output string) {
		if len(output) > 32<<10 {
			return
		}
		data, _, _ := canonical(Context{Schema: 1, Kind: "propose", Destinations: []string{"d1"}})
		j := &store.AIJob{Kind: "propose", Context: data, Bindings: json.RawMessage(`{}`)}
		result, err := validateOutput(j, output)
		if err != nil {
			return
		}
		if result.Proposal == nil {
			t.Fatal("proposal result lost")
		}
		if result.Proposal.Status == "ready" && (len(result.Proposal.Order) != 1 || result.Proposal.Order[0] != "d1") {
			t.Fatal("recipient boundary escaped")
		}
	})
}
