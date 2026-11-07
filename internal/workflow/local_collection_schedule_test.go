package workflow

import (
	"encoding/json"
	"os"
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

func TestLocalCalendarGoBrowserCanonicalFrozenSnapshots(t *testing.T) {
	raw, err := os.ReadFile("../../web/tests/fixtures/local-scheduled-arrivals.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if err = json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"waiting", "ready", "admitted", "captured"} {
		t.Run(phase, func(t *testing.T) {
			var v ScheduleArrivalView
			if err := Decode(all[phase], &v); err != nil {
				t.Fatal(err)
			}
			d, _, err := scheduleDefinition(v.Schedule)
			if err != nil || d.Source.Kind != "local.collect" || d.Collection == nil || d.Collection.Source.Kind != "local.collect" || d.Collection.Connection.Local == nil || !d.Collection.Connection.Local.ReadOnly || len(d.Effects) != 0 {
				t.Fatal("local calendar root/no-forwarding meaning differs", err)
			}
			binding, err := arrivalBinding(v.Arrival)
			if err != nil {
				t.Fatal(err)
			}
			name, err := collectionManifestName(d.Collection.Source, binding.Due)
			if err != nil || name != binding.Manifest || binding.Schedule.Hash != v.Schedule.Hash {
				t.Fatal("local UTC occurrence detached from reviewed schedule", err)
			}
			if v.Collection != nil {
				frozen, err := collectionDefinition(v.Collection.Job)
				if err != nil || frozen.SourceIdentity != collectionSourceIdentity(d.Collection.Connection) || frozen.Schedule == nil || frozen.Schedule.Schedule.Hash != v.Schedule.Hash || frozen.Schedule.OccurrenceID != v.Arrival.ID || len(frozen.Effects) != 0 {
					t.Fatal("local due collection lost exact physical root/manifest/authority", err)
				}
				for _, input := range v.Collection.Inputs {
					if input.RunID != nil || input.State != "accepted" || input.SourceIdentity != frozen.SourceIdentity {
						t.Fatal("local collection inherited a sending run")
					}
				}
			}
		})
	}
}
