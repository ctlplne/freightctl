package store

import (
	"encoding/json"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
)

func TestOnboardingProbeCanonicalDefinition(t *testing.T) {
	d := OnboardingProbeDefinition{Schema: 1, Profile: "sftp-readonly-v1", Plan: OnboardingReference{ID: "11111111-1111-4111-8111-111111111111", Version: 3, Hash: strings.Repeat("a", 64)}, RequirementID: "22222222-2222-4222-8222-222222222222", Connection: OnboardingReference{ID: "33333333-3333-4333-8333-333333333333", Version: 2, Hash: strings.Repeat("b", 64)}, Authority: 7}
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if secure.Digest(data) != "0588ff43f2acdc0b70ed2956670581b8650df0b5db024cb797639fe33e5b299e" {
		t.Fatal("Go/browser canonical probe contract changed")
	}
}
