package workflow

import (
	"testing"
	"time"
)

func TestLocalCollectionCalendarUsesExactUTCManifestAndKeepsReadOnlyRoot(t *testing.T) {
	source := collectionTestSource()
	source.Kind = "local.collect"
	source.Contract = ScheduledCollectionContract
	source.Manifest = "settlement-{due_utc}.ready.json"
	if err := normalizeCollectionSource(source); err != nil {
		t.Fatal("reviewed local UTC manifest contract unavailable", err)
	}
	if _, err := Normalize(Definition{Schema: 1, Name: "Approved local calendar source", Steps: []Step{}, Source: &source}); err != nil {
		t.Fatal("ordinary local scheduled workflow refused", err)
	}
	due := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("first-fold", -4*3600))
	first, err := collectionManifestName(source, due)
	if err != nil || first != "settlement-20261101T053000Z.ready.json" {
		t.Fatal("local due manifest lost exact UTC meaning", err)
	}
	second, err := collectionManifestName(source, due.Add(time.Hour))
	if err != nil || second == first || second != "settlement-20261101T063000Z.ready.json" {
		t.Fatal("repeated local time reused earlier producer manifest", err)
	}
	for _, name := range []string{"settlement.ready.json", "{due_utc}-{due_utc}.ready.json", "../{due_utc}.ready.json", "{local_time}.ready.json", "{due_utc}/one.ready.json"} {
		source.Manifest = name
		if normalizeCollectionSource(source) == nil {
			t.Fatal("ambiguous local scheduled producer claim admitted", name)
		}
	}
}
