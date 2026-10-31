package workflow

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestScheduledCollectionSourceRequiresOneBoundedUTCManifestToken(t *testing.T) {
	source := collectionTestSource()
	source.Contract = "immutable-files-sha256-scheduled-manifest-v1"
	source.Manifest = "settlement-{due_utc}.ready.json"
	if err := normalizeCollectionSource(source); err != nil {
		t.Fatalf("a reviewed per-occurrence manifest cannot be configured: %v", err)
	}
	for _, filename := range []string{
		"settlement.ready.json", "{due_utc}-{due_utc}.ready.json",
		"../{due_utc}.ready.json", "settlement-{local_time}.ready.json",
		"settlement-{due_utc}.csv", "{due_utc}/batch.ready.json",
	} {
		source.Manifest = filename
		if normalizeCollectionSource(source) == nil {
			t.Fatalf("ambiguous or unsafe scheduled manifest accepted: %q", filename)
		}
	}
}

func TestScheduledArrivalGoBrowserCanonicalFrozenSnapshots(t *testing.T) {
	data, err := os.ReadFile("../../web/tests/fixtures/scheduled-arrivals.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"waiting", "ready", "admitted", "captured"} {
		t.Run(phase, func(t *testing.T) {
			var v ScheduleArrivalView
			if err := Decode(fixtures[phase], &v); err != nil {
				t.Fatal(err)
			}
			binding, err := arrivalBinding(v.Arrival)
			if err != nil {
				t.Fatal(err)
			}
			d, _, err := scheduleDefinition(v.Schedule)
			if err != nil {
				t.Fatal(err)
			}
			name, err := collectionManifestName(d.Collection.Source, binding.Due)
			if err != nil || name != binding.Manifest {
				t.Fatal(name, err)
			}
			if v.Arrival.ManifestHash != nil {
				_, hash, err := parseCollectionManifest(v.Arrival.Manifest, d.Collection.Source)
				if err != nil || hash != *v.Arrival.ManifestHash {
					t.Fatal(hash, err)
				}
			}
			if v.Collection != nil {
				job, err := collectionDefinition(v.Collection.Job)
				if err != nil || job.Schedule == nil || job.Schedule.OccurrenceID != v.Arrival.ID || job.Schedule.ManifestHash != *v.Arrival.ManifestHash {
					t.Fatal(job, err)
				}
			}
		})
	}
}

func TestScheduledManifestUTCNamesDistinguishRepeatedLocalClockTimes(t *testing.T) {
	source := collectionTestSource()
	source.Contract = ScheduledCollectionContract
	source.Manifest = "settlement-{due_utc}.ready.json"
	first, _ := time.Parse(time.RFC3339, "2026-11-01T01:30:00-04:00")
	second, _ := time.Parse(time.RFC3339, "2026-11-01T01:30:00-05:00")
	a, e := collectionManifestName(source, first)
	if e != nil {
		t.Fatal(e)
	}
	b, e := collectionManifestName(source, second)
	if e != nil {
		t.Fatal(e)
	}
	if a != "settlement-20261101T053000Z.ready.json" || b != "settlement-20261101T063000Z.ready.json" || a == b {
		t.Fatal("repeated local time reused an input identity", a, b)
	}
}
