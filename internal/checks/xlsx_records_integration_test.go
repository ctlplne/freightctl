//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func xlsxStockBytes(t testing.TB, name string) []byte {
	t.Helper()
	root := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
	if root == "" {
		t.Fatal("actual stock XLSX source directory is required")
	}
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestXLSXRecordsActualHeldCustodyCheckSeparateReleaseAndRecheck(t *testing.T) {
	goodXLSX := string(xlsxStockBytes(t, "shared.xlsx"))
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	registered, err := s.Register(f.ctx, f.scope, "xlsx-policy", PolicyRequest{Definition: xlsxIntakePolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var config store.Configuration
	if json.Unmarshal(registered.Resource, &config) != nil {
		t.Fatal("XLSX policy receipt")
	}
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "xlsx-source", int64(len(goodXLSX)), secure.Digest([]byte(goodXLSX)), strings.NewReader(goodXLSX), custody.UploadTarget{Path: "/records.xlsx"})
	if err != nil || file.Policy != store.XLSXRecordsIntakePrefix+config.Hash || custody.Acceptance(file) != "durable-held-pending-checks-and-release" {
		t.Fatal("XLSX custody identity/hold", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("unchecked XLSX bytes exposed", err)
	}
	for i := 0; i < 2; i++ {
		r, e := s.Run(f.ctx, f.scope, file.ID, "xlsx-check")
		if e != nil || r.Replayed != (i == 1) {
			t.Fatal("XLSX original check key", e)
		}
	}
	current := getCheck(t, s, f, file.ID)
	var report Report
	if json.Unmarshal(current.Report, &report) != nil || current.State != "passed" || current.Attempts != 1 || report.Engine != "freightctl-xlsx-records-v1" || report.Code != "valid_xlsx_records" || report.Rows != 1 || report.Bytes != file.Size || report.SHA256 != file.SHA256 || report.PolicyHash != config.Hash {
		t.Fatal("XLSX check report lost exact format/source")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("parser pass bypassed release", err)
	}
	wrong := releaseDecision(current)
	wrong.ReportHash = strings.Repeat("f", 64)
	if _, err = s.Release(f.ctx, f.scope, file.ID, "xlsx-wrong-release", wrong); !errors.Is(err, store.ErrRevision) {
		t.Fatal("wrong XLSX report approved", err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "xlsx-release", releaseDecision(current)); err != nil {
		t.Fatal(err)
	}
	original := getCheck(t, s, f, file.ID)
	policy := xlsxIntakePolicy(t)
	policy.MaxRows++
	if _, err = s.Register(f.ctx, f.scope, "xlsx-policy-two", PolicyRequest{ExpectedVersion: 1, Definition: policy}); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewRecheck(f.ctx, f.scope, file.ID, RecheckOptions{TargetPath: "/xlsx-rechecked.dat", SignatureMode: "not_required", Reason: "Fresh exact checks under the new xlsx-width policy"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.ProposeRecheck(f.ctx, f.scope, "xlsx-recheck", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	intent := recheckRow(t, r)
	if _, err = s.DecideRecheck(f.ctx, f.scope, intent.ID, "xlsx-recheck-approve", PolicyRecheckDecision{Operation: "approve", Hash: intent.Hash, Revision: intent.Revision}); err != nil {
		t.Fatal(err)
	}
	r, err = s.CopyRecheck(f.ctx, f.scope, intent.ID, "xlsx-copy")
	if err != nil {
		t.Fatal(err)
	}
	var child RecheckCopyResult
	if json.Unmarshal(recheckRow(t, r).Result, &child) != nil || child.File.ID == file.ID || child.File.SHA256 != file.SHA256 || !strings.HasPrefix(child.File.Policy, store.XLSXRecordsIntakePrefix) || child.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal("XLSX recheck inherited release or changed bytes")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, child.File.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("XLSX recheck copy exposed", err)
	}
	if _, err = s.Run(f.ctx, f.scope, child.File.ID, "xlsx-child-check"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, child.File.ID, "xlsx-child-release", releaseDecision(getCheck(t, s, f, child.File.ID))); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.DownloadPath(f.ctx, f.scope, "/xlsx-rechecked.dat")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(reader, file.Size+1))
	reader.Close()
	if err != nil || !bytes.Equal(got, []byte(goodXLSX)) {
		t.Fatal("independent XLSX byte observation", err)
	}
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(getCheck(t, s, f, file.ID))
	if !sameJSON(a, b) {
		t.Fatal("XLSX recheck rewrote original evidence")
	}
}
