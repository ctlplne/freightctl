package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestProjectionStageRetainsPartialAdoptsExactSealedAndRefusesTampering(t *testing.T) {
	_, d, _ := projectionIntentFixture(t)
	source, _ := projectionContract(t)
	root := filepath.Join(t.TempDir(), "freightctl-projection-stage")
	disk, err := custody.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	scope := store.Scope{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "99999999-9999-4999-8999-999999999999"}
	f := d.Plan.Context.Source.File
	if err = disk.Stage(custody.Name(scope.Tenant, scope.Partner, f.ID), strings.NewReader(projectionInput), f.Size, f.SHA256); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(root, custody.Name(scope.Tenant, scope.Partner, d.Slots[0]))
	partialFile, err := protectedfs.CreateExclusive(partial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = partialFile.Write([]byte("interrupted task-owned output")); err != nil {
		partialFile.Close()
		t.Fatal(err)
	}
	if err = partialFile.Close(); err != nil {
		t.Fatal(err)
	}
	guard := func() error { return nil }
	out, report, err := stageProjection(t.Context(), disk, scope, source, d, 8192, 1<<20, guard)
	if err != nil || out.ID != d.Slots[1] || out.SHA256 != report.OutputSHA256 || out.Size != report.OutputBytes {
		t.Fatal("complete held candidate not staged", err)
	}
	name := filepath.Join(root, custody.Name(scope.Tenant, scope.Partner, out.ID))
	before, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	again, second, err := stageProjection(t.Context(), disk, scope, source, d, 8192, 1<<20, guard)
	if err != nil || *out != *again || second.OutputSHA256 != report.OutputSHA256 {
		t.Fatal("exact uncertain-commit object not adopted", err)
	}
	after, err := os.Stat(name)
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("adoption replaced or unsealed original", err)
	}
	if data, err := os.ReadFile(partial); err != nil || string(data) != "interrupted task-owned output" {
		t.Fatal("partial slot was erased or reused", err)
	}
	requireSealedProjectionForTest(t, name)
	rewriteSealedProjectionForTest(t, name, []byte("tampered"))
	requireSealedProjectionForTest(t, name)
	tampered, err := os.Stat(name)
	if err != nil || !os.SameFile(after, tampered) {
		t.Fatal("tamper fixture replaced the original physical object", err)
	}
	if file, r, err := stageProjection(t.Context(), disk, scope, source, d, 8192, 1<<20, guard); !errors.Is(err, custody.ErrIntegrity) || file != nil || r.OutputSHA256 != "" {
		t.Fatal("tampering was hidden by choosing another slot", err)
	}
}

func TestProjectionStageGuardAndQuotaCannotQualifyOrRetainNewPartial(t *testing.T) {
	_, d, _ := projectionIntentFixture(t)
	source, _ := projectionContract(t)
	root := filepath.Join(t.TempDir(), "freightctl-projection-guard")
	disk, err := custody.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	scope := store.Scope{Tenant: "11111111-1111-4111-8111-111111111111", Partner: "99999999-9999-4999-8999-999999999999"}
	f := d.Plan.Context.Source.File
	if err = disk.Stage(custody.Name(scope.Tenant, scope.Partner, f.ID), strings.NewReader(projectionInput), f.Size, f.SHA256); err != nil {
		t.Fatal(err)
	}
	count := 0
	guard := func() error {
		count++
		if count > 1 {
			return context.Canceled
		}
		return nil
	}
	if file, r, err := stageProjection(t.Context(), disk, scope, source, d, 8192, 1<<20, guard); !errors.Is(err, context.Canceled) || file != nil || r.OutputSHA256 != "" {
		t.Fatal("lost processing guard produced output", err)
	}
	for _, id := range d.Slots {
		if _, err = os.Stat(filepath.Join(root, custody.Name(scope.Tenant, scope.Partner, id))); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed new staging object survived", err)
		}
	}
	if file, r, err := stageProjection(t.Context(), disk, scope, source, d, 8192, 1, func() error { return nil }); !errors.Is(err, custody.ErrCapacity) || file != nil || r.OutputSHA256 != "" {
		t.Fatal("storage quota bypassed", err)
	}
}

func requireSealedProjectionForTest(t testing.TB, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	state, err := protectedfs.Protection(f)
	if err != nil || state != protectedfs.PrivateSealed {
		t.Fatal("original projection object is not private sealed bytes", err)
	}
}
