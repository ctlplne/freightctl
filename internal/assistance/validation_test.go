package assistance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
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

func TestCredentialFieldsCannotLeavePartiallyRedactedOperatorText(t *testing.T) {
	for _, tc := range []struct {
		name, text string
	}{
		{"basic authorization", "Authorization: Basic dXNlcjpwYXNz"},
		{"folded proxy authorization", "Proxy-Authorization: Digest\r\n  username=\"example\", response=\"tiny\""},
		{"quoted password", "send the report; password=\"two words\""},
		{"JSON secret", `{"client_secret": "tiny synthetic secret"}`},
		{"environment token", "EXAMPLE_ACCESS_TOKEN=tiny"},
		{"cookie header", "Cookie: sid=tiny; session=other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := redact(tc.text, nil)
			if err != nil || got != "[credential-bearing text redacted]" {
				t.Fatal("credential field did not suppress the entire submitted text")
			}
		})
	}
	got, err := redact("Send the approved file at 07:00, then obtain its receipt.", nil)
	if err != nil || got != "Send the approved file at 07:00, then obtain its receipt." {
		t.Fatal("ordinary requirements lost their meaning", err)
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
		`{"status":"ready","order":["d1","d2"],"missing":[],"ftps_destinations":["d1"]}`,
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

func TestProposalOrderKeepsTheReviewedDeliveryProtocol(t *testing.T) {
	const sftp = "00000000-0000-4000-8000-000000000001"
	const ftps = "00000000-0000-4000-8000-000000000002"
	bindings, _, err := canonical(Bindings{Request: PrepareRequest{
		Name: "ordered exports",
		Destinations: []Destination{
			{Connection: workflow.Reference{ID: sftp, Version: 1, Hash: strings.Repeat("a", 64)}, Filename: "first.csv"},
			{Connection: workflow.Reference{ID: ftps, Version: 2, Hash: strings.Repeat("b", 64)}, Filename: "second.csv"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	job := &store.AIJob{
		Kind: "propose", Bindings: bindings,
		Context: json.RawMessage(`{"schema_version":1,"kind":"propose","destinations":["d1","d2"],"ftps_destinations":["d2"]}`),
		Result:  json.RawMessage(`{"proposal":{"status":"ready","order":["d2","d1"],"missing":[]}}`),
	}
	def, err := proposedDefinition(job)
	if err != nil || len(def.Steps) != 2 {
		t.Fatal("reviewed delivery order was not compiled", err)
	}
	for i, expected := range []struct{ id, kind, filename string }{
		{ftps, "ftps.deliver", "second.csv"}, {sftp, "sftp.deliver", "first.csv"},
	} {
		step := def.Steps[i]
		if step.Connection.ID != expected.id || step.Kind != expected.kind || step.Filename != expected.filename {
			t.Fatalf("step %d changed its reviewed protocol, receiver or filename", i+1)
		}
	}
	job.Result = json.RawMessage(`{"proposal":{"status":"ready","order":["d2","d1"],"missing":null}}`)
	legacy, err := proposedDefinition(job)
	if err != nil || len(legacy.Steps) != 2 || legacy.Steps[0] != def.Steps[0] || legacy.Steps[1] != def.Steps[1] {
		t.Fatal("legacy stored successful proposal lost its exact draft", err)
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

func TestModelOutputRequiresExplicitBoundedArrays(t *testing.T) {
	for _, tc := range []struct{ name, kind, body string }{
		{"omitted missing", "propose", `{"status":"ready","order":["d1"]}`},
		{"null missing", "propose", `{"status":"ready","order":["d1"],"missing":null}`},
		{"omitted order", "propose", `{"status":"needs_input","missing":["filename"]}`},
		{"repeated missing", "propose", `{"status":"needs_input","order":[],"missing":["filename","filename"]}`},
		{"omitted abstention evidence", "diagnose", `{"code":"insufficient_evidence","next_check":"gather_evidence"}`},
		{"null abstention evidence", "diagnose", `{"code":"insufficient_evidence","evidence":null,"next_check":"gather_evidence"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contextData, _, _ := canonical(Context{Schema: 1, Kind: tc.kind, Destinations: []string{"d1"}})
			job := &store.AIJob{Kind: tc.kind, Context: contextData, Bindings: json.RawMessage(`{}`)}
			if result, err := validateOutput(job, tc.body); result != nil || err != ErrModelOutput {
				t.Fatal("a model decision outside the published array contract was accepted")
			}
		})
	}
	for _, tc := range []struct{ kind, body string }{
		{"propose", `{"status":"needs_input","order":[],"missing":["filename"]}`},
		{"diagnose", `{"code":"insufficient_evidence","evidence":[],"next_check":"gather_evidence"}`},
	} {
		contextData, _, _ := canonical(Context{Schema: 1, Kind: tc.kind, Destinations: []string{"d1"}})
		job := &store.AIJob{Kind: tc.kind, Context: contextData, Bindings: json.RawMessage(`{}`)}
		if result, err := validateOutput(job, tc.body); result == nil || err != nil {
			t.Fatal("an explicit empty array lost its intended meaning", err)
		}
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
