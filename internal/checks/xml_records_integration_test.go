//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

const goodXMLRecords = "<?xml version='1.0' encoding='utf-8'?>\n<records><record><account>0001</account><amount>100.01</amount><day>2026-10-28</day></record></records>"

func TestXMLRecordsActualHeldCustodyCheckSeparateReleaseAndRecheck(t *testing.T) {
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	registered, err := s.Register(f.ctx, f.scope, "xml-policy", PolicyRequest{Definition: xmlRecordsPolicy(t)})
	if err != nil {
		t.Fatal(err)
	}
	var config store.Configuration
	if json.Unmarshal(registered.Resource, &config) != nil {
		t.Fatal("XML policy receipt")
	}
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "xml-source", int64(len(goodXMLRecords)), secure.Digest([]byte(goodXMLRecords)), strings.NewReader(goodXMLRecords), custody.UploadTarget{Path: "/records.xml"})
	if err != nil || file.Policy != store.XMLRecordsIntakePrefix+config.Hash || custody.Acceptance(file) != "durable-held-pending-checks-and-release" {
		t.Fatal("XML custody identity/hold", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("unchecked XML bytes exposed", err)
	}
	for i := 0; i < 2; i++ {
		r, e := s.Run(f.ctx, f.scope, file.ID, "xml-check")
		if e != nil || r.Replayed != (i == 1) {
			t.Fatal("XML original check key", e)
		}
	}
	current := getCheck(t, s, f, file.ID)
	var report Report
	if json.Unmarshal(current.Report, &report) != nil || current.State != "passed" || current.Attempts != 1 || report.Engine != "freightctl-xml-records-v1" || report.Code != "valid_xml_records" || report.Rows != 1 || report.Bytes != file.Size || report.SHA256 != file.SHA256 || report.PolicyHash != config.Hash {
		t.Fatal("XML check report lost exact format/source")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("parser pass bypassed release", err)
	}
	wrong := releaseDecision(current)
	wrong.ReportHash = strings.Repeat("f", 64)
	if _, err = s.Release(f.ctx, f.scope, file.ID, "xml-wrong-release", wrong); !errors.Is(err, store.ErrRevision) {
		t.Fatal("wrong XML report approved", err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "xml-release", releaseDecision(current)); err != nil {
		t.Fatal(err)
	}
	original := getCheck(t, s, f, file.ID)
	policy := xmlRecordsPolicy(t)
	policy.MaxRows++
	if _, err = s.Register(f.ctx, f.scope, "xml-policy-two", PolicyRequest{ExpectedVersion: 1, Definition: policy}); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewRecheck(f.ctx, f.scope, file.ID, RecheckOptions{TargetPath: "/xml-rechecked.dat", SignatureMode: "not_required", Reason: "Fresh exact checks under the new xml-width policy"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.ProposeRecheck(f.ctx, f.scope, "xml-recheck", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	intent := recheckRow(t, r)
	if _, err = s.DecideRecheck(f.ctx, f.scope, intent.ID, "xml-recheck-approve", PolicyRecheckDecision{Operation: "approve", Hash: intent.Hash, Revision: intent.Revision}); err != nil {
		t.Fatal(err)
	}
	r, err = s.CopyRecheck(f.ctx, f.scope, intent.ID, "xml-copy")
	if err != nil {
		t.Fatal(err)
	}
	var child RecheckCopyResult
	if json.Unmarshal(recheckRow(t, r).Result, &child) != nil || child.File.ID == file.ID || child.File.SHA256 != file.SHA256 || !strings.HasPrefix(child.File.Policy, store.XMLRecordsIntakePrefix) || child.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal("XML recheck inherited release or changed bytes")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, child.File.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("XML recheck copy exposed", err)
	}
	if _, err = s.Run(f.ctx, f.scope, child.File.ID, "xml-child-check"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Release(f.ctx, f.scope, child.File.ID, "xml-child-release", releaseDecision(getCheck(t, s, f, child.File.ID))); err != nil {
		t.Fatal(err)
	}
	_, reader, err := s.Custody.DownloadPath(f.ctx, f.scope, "/xml-rechecked.dat")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.LimitReader(reader, file.Size+1))
	reader.Close()
	if err != nil || !bytes.Equal(got, []byte(goodXMLRecords)) {
		t.Fatal("independent XML byte observation", err)
	}
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(getCheck(t, s, f, file.ID))
	if !sameJSON(a, b) {
		t.Fatal("XML recheck rewrote original evidence")
	}
}
