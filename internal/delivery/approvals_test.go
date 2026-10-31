package delivery

import (
	"encoding/json"
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
	var f map[string]struct {
		Selection DispatchSelection            `json:"selection"`
		Preview   DispatchPreview              `json:"preview"`
		Review    store.OutboundDispatchReview `json:"review"`
	}
	if json.Unmarshal(data, &f) != nil || len(f) != 2 {
		t.Fatal("fixture")
	}
	for name, v := range f {
		t.Run(name, func(t *testing.T) {
			_, hash, err := dispatchDigest(v.Preview.Definition)
			if err != nil || hash != v.Preview.Hash || hash != v.Review.Hash || v.Preview.ExternalContact || v.Preview.GrantsFileAccess {
				t.Fatal("canonical metadata/flags", hash, err)
			}
			d := v.Preview.Definition
			if d.DeliveryHash != v.Selection.Hash || d.DeliveryID != v.Selection.DeliveryID || d.DeliveryRevision != v.Selection.Revision || d.Reviewer != v.Selection.ReviewerID || d.Effect.KeyReferenceHash == "" {
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
