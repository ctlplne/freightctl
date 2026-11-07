package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
)

func TestSetupPlanPreservesCredentialAndRefusesChangedReferences(t *testing.T) {
	dir := privateCLIDirectory(t)
	planFile, tokenFile, storage := filepath.Join(dir, "setup.json"), filepath.Join(dir, "admin.token"), filepath.Join(dir, "custody")
	if err := prepareSetup(planFile, tokenFile, storage, "Tenant", "Partner", "Administrator"); err != nil {
		t.Fatal(err)
	}
	requireSealedCLIOutput(t, planFile)
	data, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatal(err)
	}
	var plan setupPlan
	if err = json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	token, err := secure.ReadSecret(tokenFile, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	if strings.Contains(string(data), string(token.Bytes)) || secure.Digest(token.Bytes) != plan.Request.Credential {
		t.Fatal("plan contains credential value or wrong proof")
	}
	if err = prepareSetup(planFile, tokenFile, storage, "Other", "Other", "Other"); err == nil {
		t.Fatal("plan overwritten")
	}
	after, _ := os.ReadFile(planFile)
	if string(after) != string(data) {
		t.Fatal("failed retry changed plan")
	}
	wrong, err := custody.Open(filepath.Join(dir, "other-custody"))
	if err != nil {
		t.Fatal(err)
	}
	wrong.Close()
	plan.Storage = filepath.Join(dir, "other-custody")
	mutated, _ := json.Marshal(plan)
	changed := filepath.Join(dir, "changed.json")
	writeProtectedCLIReference(t, changed, mutated)
	if _, err = applySetup(context.Background(), "absent-admin-reference", changed); err == nil || !strings.Contains(err.Error(), "storage identity changed") {
		t.Fatal("changed storage reached SQL", err)
	}
	plan.Storage = storage
	plan.Request.Credential = secure.Digest([]byte("other credential"))
	mutated, _ = json.Marshal(plan)
	changed = filepath.Join(dir, "changed-credential.json")
	writeProtectedCLIReference(t, changed, mutated)
	if _, err = applySetup(context.Background(), "absent-admin-reference", changed); err == nil || !strings.Contains(err.Error(), "credential changed") {
		t.Fatal("changed credential reached SQL", err)
	}
}
