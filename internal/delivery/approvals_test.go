package delivery

import (
	"encoding/json"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"os"
	"reflect"
	"testing"
)

func TestOutboundDispatchGoBrowserCanonicalMetadataAndNoContact(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/outbound-dispatch.json")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the public reference input and fixed canonical hashes in the golden
	// fixture. Independently derive its reference fingerprint here and in Node;
	// this is not a password digest or a captured credential-bearing response.
	var templates map[string]map[string]json.RawMessage
	if json.Unmarshal(data, &templates) != nil {
		t.Fatal("fixture templates")
	}
	derived := 0
	object := func(value any) map[string]any {
		t.Helper()
		v, ok := value.(map[string]any)
		if !ok {
			t.Fatal("fixture object")
		}
		return v
	}
	for _, fields := range templates {
		input, ok := fields["public_reference_input"]
		if !ok {
			continue
		}
		var reference string
		if json.Unmarshal(input, &reference) != nil || reference != "/synthetic/receiver-password-reference" {
			t.Fatal("public fixture reference")
		}
		for _, section := range []string{"preview", "review", "view"} {
			var value map[string]any
			if json.Unmarshal(fields[section], &value) != nil {
				t.Fatal("fixture section")
			}
			definition := value
			if section != "view" {
				definition = object(value["definition"])
			}
			ftps := object(object(definition["effect"])["ftps"])
			if value, present := ftps["password_reference_sha256"]; !present || value != nil {
				t.Fatal("derived fixture placeholder")
			}
			ftps["password_reference_sha256"] = secure.Digest([]byte(reference))
			fields[section], err = json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			derived++
		}
	}
	if derived != 18 {
		t.Fatal("missing derived reference cases")
	}
	data, err = json.Marshal(templates)
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]struct {
		Selection DispatchSelection            `json:"selection"`
		Preview   DispatchPreview              `json:"preview"`
		Review    store.OutboundDispatchReview `json:"review"`
	}
	if json.Unmarshal(data, &f) != nil || len(f) != 8 {
		t.Fatal("fixture")
	}
	for name, v := range f {
		t.Run(name, func(t *testing.T) {
			_, hash, err := dispatchDigest(v.Preview.Definition)
			if err != nil || hash != v.Preview.Hash || hash != v.Review.Hash || v.Preview.ExternalContact || v.Preview.GrantsFileAccess {
				t.Fatal("canonical metadata/flags", hash, err)
			}
			d := v.Preview.Definition
			if d.DeliveryHash != v.Selection.Hash || d.DeliveryID != v.Selection.DeliveryID || d.DeliveryRevision != v.Selection.Revision || d.Reviewer != v.Selection.ReviewerID || (d.Schema == 1 && d.Effect.KeyReferenceHash == "") || (d.Schema == 2 && (d.Effect.FTPS == nil || d.Effect.FTPS.PasswordReferenceHash == "")) {
				t.Fatal("binding")
			}
		})
	}
	var raw map[string]map[string]json.RawMessage
	json.Unmarshal(data, &raw)
	for name, v := range f {
		var expected, actual any
		json.Unmarshal(raw[name]["preview"], &expected)
		encoded, _ := json.Marshal(v.Preview)
		json.Unmarshal(encoded, &actual)
		if !reflect.DeepEqual(expected, actual) {
			t.Fatal("metadata shape changed", name)
		}
	}
}
