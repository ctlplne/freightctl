package namespaceprops

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPropertyTransactionIsAtomicOrderedAndCannotChangeLiveAuthority(t *testing.T) {
	original := map[string]string{"{urn:example}p": `<x:p xmlns:x="urn:example">original</x:p>`}
	before := clone(original)
	for _, namespace := range []string{"DAV:", "urn:freightctl", "urn:freightctl:namespace", "urn:freightctl:future"} {
		_, err := Apply(original, []Change{{"set", `<x:p xmlns:x="urn:example">changed</x:p>`}, {"set", fmt.Sprintf(`<x:execute xmlns:x="%s">approved</x:execute>`, namespace)}})
		if !errors.Is(err, ErrProtected) || !reflect.DeepEqual(original, before) {
			t.Fatal("protected name partially committed or changed input", err)
		}
	}
	next, err := Apply(original, []Change{{"set", `<x:p xmlns:x="urn:example">changed</x:p>`}, {"remove", `<x:p xmlns:x="urn:example"/>`}, {"remove", `<x:missing xmlns:x="urn:example"/>`}, {"set", `<x:p xmlns:x="urn:example"><x:execute approved="true">data only</x:execute></x:p>`}})
	if err != nil || len(next) != 1 || !strings.Contains(next["{urn:example}p"], "data only") || !reflect.DeepEqual(original, before) {
		t.Fatal("ordered inert property data changed semantics", err)
	}
}

func TestPropertySnapshotsRefuseCorruptionAndFiniteCapacityWithoutPartialResults(t *testing.T) {
	for _, properties := range []map[string]string{
		{"{urn:example}other": `<x:p xmlns:x="urn:example"/>`},
		{"{urn:example}p": `<x:p/>`},
		{"{urn:example}p": `<?xml version="1.0"?><x:p xmlns:x="urn:example"/>`},
		{"{DAV:}getetag": `<getetag xmlns="DAV:">fake</getetag>`},
	} {
		if err := Validate(properties); err == nil {
			t.Fatal("persisted corruption trusted")
		}
	}
	full := map[string]string{}
	for i := 0; i < MaxChanges; i++ {
		full[fmt.Sprintf("{urn:example}p%d", i)] = fmt.Sprintf(`<p%d xmlns="urn:example"/>`, i)
	}
	before := clone(full)
	if next, err := Apply(full, []Change{{"set", `<extra xmlns="urn:example"/>`}}); !errors.Is(err, ErrLimit) || next != nil || !reflect.DeepEqual(full, before) {
		t.Fatal("property count overflow partially accepted", err)
	}
	if next, err := Apply(nil, []Change{{"set", `<p xmlns="urn:example">` + strings.Repeat("&amp;", MaxSnapshotBytes) + `</p>`}}); !errors.Is(err, ErrLimit) || next != nil {
		t.Fatal("oversized intent accepted", err)
	}
}
