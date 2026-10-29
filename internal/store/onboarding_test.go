package store

import (
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func onboardingGolden() OnboardingCommand {
	return OnboardingCommand{ID: "11111111-1111-4111-8111-111111111111", ExpectedAuthority: 1, Definition: OnboardingDefinition{Schema: 1, Name: "Payroll <A> & B", Contacts: []OnboardingContact{{ID: "22222222-2222-4222-8222-222222222222", Name: "José", Role: "Operations", Email: "ops@freightctl.invalid", Phone: ""}}, Requirements: []OnboardingRequirement{{ID: "33333333-3333-4333-8333-333333333333", Name: "Settlement", ContactID: "22222222-2222-4222-8222-222222222222", Direction: "send", Protocol: "sftp", Receipt: "business", ReceiptContract: "ACK-v1", Notes: "\nReceiver > note\u2028second\tline\r\n"}}}}
}

func TestOnboardingCanonicalDefinitionAndInputBounds(t *testing.T) {
	c := onboardingGolden()
	normalized, err := normalizeOnboarding(c)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(normalized.Definition)
	t.Log("canonical_sha256=" + secure.Digest(data))
	if secure.Digest(data) != "718145463a3ffecc6e54e2bd41cac37e08a1371512b81c02f430703859918179" {
		t.Fatal("cross-language canonical definition changed")
	}
	if !strings.Contains(string(data), `Payroll \u003cA\u003e \u0026 B`) || !strings.Contains(string(data), `\u2028`) || !strings.Contains(string(data), `\r\n`) {
		t.Fatal("canonical HTML or line ending representation changed")
	}
	normalized.Definition.Contacts[0].Name = "changed copy"
	if c.Definition.Contacts[0].Name != "José" {
		t.Fatal("normalizer aliases caller-owned contact storage")
	}
	for _, name := range []string{"foreign-contact", "duplicate-contact", "invalid-direction", "invented-receipt", "oversize", "control-name", "non-nfc", "display-name-email"} {
		t.Run(name, func(t *testing.T) {
			v := onboardingGolden()
			switch name {
			case "foreign-contact":
				v.Definition.Requirements[0].ContactID = v.ID
			case "duplicate-contact":
				v.Definition.Contacts = append(v.Definition.Contacts, v.Definition.Contacts[0])
			case "invalid-direction":
				v.Definition.Requirements[0].Direction = "execute"
			case "invented-receipt":
				v.Definition.Requirements[0].Receipt = "exactly_once"
			case "oversize":
				v.Definition.Requirements[0].Notes = strings.Repeat("x", 2049)
			case "control-name":
				v.Definition.Contacts[0].Name = "Bad\r\nname"
			case "non-nfc":
				v.Definition.Contacts[0].Name = "Jose\u0301"
			case "display-name-email":
				v.Definition.Contacts[0].Email = "Other <ops@freightctl.invalid>"
			}
			if _, err := normalizeOnboarding(v); err != ErrOnboardingInput {
				t.Fatal("invalid draft admitted", err)
			}
		})
	}
}
