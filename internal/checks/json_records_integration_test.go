//go:build integration

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
	"github.com/jackc/pgx/v5/pgconn"
)

const goodJSONRecords = "[{\"account\":\"0001\",\"amount\":1.01,\"day\":\"2026-10-28\"}]\n"

func TestJSONRecordsRecheckChangesFormatWithoutRewritingOriginalEvidence(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodJSONRecords, false)
	if _, err := s.Run(f.ctx, f.scope, source.ID, "original-csv-check"); err != nil {
		t.Fatal(err)
	}
	original := getCheck(t, s, f, source.ID)
	if original.State != "rejected" || !strings.HasPrefix(source.Policy, store.CSVIntakePrefix) {
		t.Fatal("JSON source incorrectly passed the original CSV contract")
	}
	policy := testPolicy(t)
	policy.Schema, policy.Kind = 2, "json_records"
	registered, err := s.Register(f.ctx, f.scope, "json-recheck-policy", PolicyRequest{ExpectedVersion: 1, Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var configuration store.Configuration
	if json.Unmarshal(registered.Resource, &configuration) != nil {
		t.Fatal("new JSON policy receipt")
	}
	// Approval authorizes a new held revision,not editing the original report.
	preview, err := s.PreviewRecheck(f.ctx, f.scope, source.ID, RecheckOptions{TargetPath: "/rechecked.json", SignatureMode: "not_required", Reason: "Review the exact bytes against the separately approved JSON contract"})
	if err != nil || preview.Plan.Source.File.Policy != source.Policy || preview.Plan.Policy.Hash != configuration.Hash || preview.PreviousPolicy == nil || preview.PreviousPolicy.Definition.Kind != "csv" || preview.CurrentPolicy.Definition.Kind != "json_records" {
		t.Fatal("cross-format review lost original or current bindings", err)
	}
	saved, err := s.ProposeRecheck(f.ctx, f.scope, "json-recheck-proposal", preview.Plan)
	if err != nil {
		t.Fatal(err)
	}
	r := recheckRow(t, saved)
	if _, err = s.CopyRecheck(f.ctx, f.scope, r.ID, "unapproved-json-copy"); !errors.Is(err, store.ErrState) {
		t.Fatal("format choice granted copy authority", err)
	}
	if _, err = s.DecideRecheck(f.ctx, f.scope, r.ID, "json-recheck-approval", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision}); err != nil {
		t.Fatal(err)
	}
	copied, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "json-recheck-copy")
	if err != nil {
		t.Fatal(err)
	}
	var result RecheckCopyResult
	if json.Unmarshal(recheckRow(t, copied).Result, &result) != nil || result.File.ID == source.ID || result.File.Size != source.Size || result.File.SHA256 != source.SHA256 || result.File.Policy != store.JSONRecordsIntakePrefix+configuration.Hash || result.Acceptance != "durable-held-pending-checks-and-release" {
		t.Fatal("format recheck changed bytes or inherited release")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, result.File.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("recheck approval published unchecked JSON bytes", err)
	}
	replay, err := s.CopyRecheck(f.ctx, f.scope, r.ID, "json-recheck-copy")
	if err != nil || !replay.Replayed || !sameJSON(copied.Resource, replay.Resource) {
		t.Fatal("cross-format copy retry changed its effect", err)
	}
	if _, err = s.Run(f.ctx, f.scope, result.File.ID, "json-recheck-run"); err != nil {
		t.Fatal(err)
	}
	child := getCheck(t, s, f, result.File.ID)
	var report Report
	if child.State != "passed" || json.Unmarshal(child.Report, &report) != nil || report.Engine != "freightctl-json-records-v1" || report.Code != "valid_json_records" {
		t.Fatal("fresh copy did not use the approved JSON engine")
	}
	if _, err = s.Release(f.ctx, f.scope, result.File.ID, "json-recheck-release", releaseDecision(child)); err != nil {
		t.Fatal(err)
	}
	actual, reader, err := s.Custody.DownloadPath(f.ctx, f.scope, "/rechecked.json")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(io.LimitReader(reader, source.Size+1))
	reader.Close()
	if err != nil || actual.ID != result.File.ID || !bytes.Equal(body, []byte(goodJSONRecords)) {
		t.Fatal("cross-format recheck changed the exact source bytes", err)
	}
	before, _ := json.Marshal(original)
	after, _ := json.Marshal(getCheck(t, s, f, source.ID))
	if !sameJSON(before, after) {
		t.Fatal("JSON recheck rewrote the original CSV report")
	}
}

func TestJSONRecordsActualCustodyCheckAndSeparateExactRelease(t *testing.T) {
	f := setup(t)
	s := &Service{Custody: f.wf.Custody}
	policy := testPolicy(t)
	policy.Schema, policy.Kind = 2, "json_records"
	registered, err := s.Register(f.ctx, f.scope, "json-policy", PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var configuration store.Configuration
	if json.Unmarshal(registered.Resource, &configuration) != nil {
		t.Fatal("policy result")
	}
	mode := uint32(0600)
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "json-held", int64(len(goodJSONRecords)), secure.Digest([]byte(goodJSONRecords)), strings.NewReader(goodJSONRecords), custody.UploadTarget{Path: "/checked.json", Mode: &mode})
	if err != nil || file.Policy != store.JSONRecordsIntakePrefix+configuration.Hash || custody.Acceptance(file) != "durable-held-pending-checks-and-release" {
		t.Fatal("JSON acceptance lost its distinct held identity", err)
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("JSON bytes readable before checks/release", err)
	}
	first, err := s.Run(f.ctx, f.scope, file.ID, "json-check")
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.Run(f.ctx, f.scope, file.ID, "json-check")
	if err != nil || !again.Replayed || !sameJSON(first.Resource, again.Resource) {
		t.Fatal("original check key changed its effect", err)
	}
	current := getCheck(t, s, f, file.ID)
	var report Report
	if json.Unmarshal(current.Report, &report) != nil || current.State != "passed" || current.Attempts != 1 || report.Engine != policyEngine(policy) || report.Code != policySuccess(policy) || report.Rows != 1 || report.Bytes != file.Size || report.SHA256 != file.SHA256 {
		t.Fatal("actual JSON report does not bind exact source/policy", current.State)
	}
	if _, err = s.Custody.StatPath(f.ctx, f.scope, "/checked.json"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("parser pass published before separate approval", err)
	}
	wrong := releaseDecision(current)
	wrong.SHA256 = strings.Repeat("0", 64)
	if _, err = s.Release(f.ctx, f.scope, file.ID, "wrong-json-release", wrong); !errors.Is(err, store.ErrRevision) {
		t.Fatal("release accepted another source revision", err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "json-release", releaseDecision(current)); err != nil {
		t.Fatal(err)
	}
	accepted, reader, err := s.Custody.DownloadPath(f.ctx, f.scope, "/checked.json")
	if err != nil {
		t.Fatal(err)
	}
	received, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || accepted.ID != file.ID || accepted.SHA256 != secure.Digest(received) || !bytes.Equal(received, []byte(goodJSONRecords)) {
		t.Fatal("independent receiver bytes changed after JSON release", err)
	}
}

func TestJSONRecordsSQLRejectsCrossFormatReportsWhileKeepingExactValidTransition(t *testing.T) {
	for _, name := range []string{"csv", "json_records", "fixed_width", "xml_records", "xlsx_records"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			s := &Service{Custody: f.wf.Custody}
			policy := testPolicy(t)
			body := goodCSV
			if name == "json_records" {
				policy.Schema, policy.Kind, body = 2, "json_records", goodJSONRecords
			}
			if name == "fixed_width" {
				policy, body = fixedWidthPolicy(t), goodFixedWidth
			}
			if name == "xml_records" {
				policy, body = xmlRecordsPolicy(t), goodXMLRecords
			}
			if name == "xlsx_records" {
				policy, body = xlsxIntakePolicy(t), string(xlsxStockBytes(t, "shared.xlsx"))
			}
			if _, err := s.Register(f.ctx, f.scope, "format-policy", PolicyRequest{Definition: policy}); err != nil {
				t.Fatal(err)
			}
			file, _, err := s.Custody.Accept(f.ctx, f.scope, "format-held", int64(len(body)), secure.Digest([]byte(body)), strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			transaction, err := s.Custody.DB.Begin(f.ctx, f.scope)
			if err != nil {
				t.Fatal(err)
			}
			current, err := transaction.FileCheck(f.ctx, file.ID, true)
			if err != nil {
				t.Fatal(err)
			}
			now, err := transaction.DatabaseTime(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(30 * time.Second)
			previous := current.Revision
			current.State, current.Attempts, current.Revision, current.WorkerID, current.LeaseUntil = "running", 1, previous+1, secure.NewID(), &until
			if err = transaction.SaveFileCheck(f.ctx, current, previous); err != nil {
				t.Fatal(err)
			}
			if err = transaction.Tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			for _, forged := range []bool{true, false} {
				transaction, err := s.Custody.DB.Begin(f.ctx, f.scope)
				if err != nil {
					t.Fatal(err)
				}
				candidate := *current
				candidate.State, candidate.Revision = "passed", current.Revision+1
				engine, code := policyEngine(policy), policySuccess(policy)
				if forged {
					if name != "csv" {
						engine, code = Engine, "valid_csv"
					} else {
						engine, code = "freightctl-json-records-v1", "valid_json_records"
					}
				}
				candidate.Report, err = json.Marshal(Report{Engine: engine, Code: code, FileID: file.ID, SHA256: file.SHA256, PolicyHash: current.PolicyHash, Rows: 1, Bytes: file.Size})
				if err != nil {
					t.Fatal(err)
				}
				candidate.Code, candidate.ReportHash = code, secure.Digest(candidate.Report)
				err = transaction.SaveFileCheck(f.ctx, &candidate, current.Revision)
				transaction.Tx.Rollback(f.ctx)
				if forged {
					var constraint *pgconn.PgError
					if !errors.As(err, &constraint) || constraint.Code != "23514" {
						t.Fatal("cross-format report bypassed actual SQL guard", err)
					}
				} else if err != nil {
					t.Fatal("same bound transition rejected the actual correct format", err)
				}
			}
		})
	}
}

func TestJSONRecordsActualGnuPGAndScannerProtocolRemainCumulative(t *testing.T) {
	actualStructuredSignatureScanner(t, "json_records")
}

func TestFixedWidthActualGnuPGAndScannerProtocolRemainCumulative(t *testing.T) {
	actualStructuredSignatureScanner(t, "fixed_width")
}

func TestXMLRecordsActualGnuPGAndScannerProtocolRemainCumulative(t *testing.T) {
	actualStructuredSignatureScanner(t, "xml_records")
}

func TestXLSXRecordsActualGnuPGAndScannerProtocolRemainCumulative(t *testing.T) {
	actualStructuredSignatureScanner(t, "xlsx_records")
}

func actualStructuredSignatureScanner(t *testing.T, format string) {
	// GnuPG signs the actual structured bytes. The scanner is only its documented
	// protocol stand-in;this test makes no ClamAV/malware-detection claim.
	for _, mode := range []string{"clean", "offline", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			f, s, scanner, _, _ := scanFixture(t, mode, time.Hour, format)
			load, fingerprints := pgpBundle(t)
			sourceName, signatureName, target, expected := "source.json", "good-json.sig", "/both.json", goodJSONRecords
			if format == "fixed_width" {
				sourceName, signatureName, target, expected = "source.fixed", "good-fixed.sig", "/both.fixed", goodFixedWidth
			}
			if format == "xml_records" {
				sourceName, signatureName, target, expected = "source.xml", "good-xml.sig", "/both.xml", goodXMLRecords
			}
			if format == "xlsx_records" {
				sourceName, signatureName, target, expected = "source.xlsx", "good-xlsx.sig", "/both.xlsx", string(xlsxStockBytes(t, "shared.xlsx"))
			}
			source := load(sourceName)
			if !bytes.Equal(source, []byte(expected)) {
				t.Fatal("independent GnuPG fixture is not the exact structured record source")
			}
			registered, err := s.RegisterPGPKey(f.ctx, f.scope, "json-signer", PGPKeyRequest{Fingerprint: fingerprints["good"], PublicKey: load("good-public.gpg")})
			if err != nil {
				t.Fatal(err)
			}
			var signer PGPKeyView
			if json.Unmarshal(registered.Resource, &signer) != nil {
				t.Fatal("signer result")
			}
			policy := testPolicy(t)
			policy.Schema, policy.Kind = 2, "json_records"
			if format == "fixed_width" {
				policy = fixedWidthPolicy(t)
			}
			if format == "xml_records" {
				policy = xmlRecordsPolicy(t)
			}
			if format == "xlsx_records" {
				policy = xlsxIntakePolicy(t)
			}
			policy.Signature = &SignaturePolicy{Key: store.PGPReference{ID: signer.ID, Version: signer.Version, Hash: signer.Hash}, MaxAgeSeconds: 3600}
			policy.Scanner = &store.ScannerReference{ID: scanner.ID, Version: scanner.Version, Hash: scanner.Hash}
			if _, err = s.Register(f.ctx, f.scope, "json-both-required", PolicyRequest{ExpectedVersion: 1, Definition: policy}); err != nil {
				t.Fatal(err)
			}
			file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "json-both-source", int64(len(source)), secure.Digest(source), bytes.NewReader(source), custody.UploadTarget{Path: target})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.Run(f.ctx, f.scope, file.ID, "json-missing-signature"); !errors.Is(err, store.ErrState) || getCheck(t, s, f, file.ID).Attempts != 0 {
				t.Fatal("Structured parser spent an attempt or skipped its missing signer prerequisite", err)
			}
			current := getCheck(t, s, f, file.ID)
			if _, err = s.AttachSignature(f.ctx, f.scope, file.ID, "json-signature", file.SHA256, current.PolicyHash, current.Revision, load(signatureName)); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Run(f.ctx, f.scope, file.ID, "json-both-check"); err != nil {
				t.Fatal(err)
			}
			current = getCheck(t, s, f, file.ID)
			if mode != "clean" {
				state, code := "rejected", "scanner_blocked"
				if mode == "offline" {
					state, code = "failed", "scanner_unavailable"
				}
				if current.State != state || current.Code != code {
					t.Fatal("valid signature bypassed required scanner outcome", current.State, current.Code)
				}
				if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
					t.Fatal("non-clean structured bytes exposed", err)
				}
				return
			}
			var report Report
			if json.Unmarshal(current.Report, &report) != nil || current.State != "passed" || report.Engine != policyEngine(policy) || report.Code != policySuccess(policy) || report.Signature == nil || report.Signature.Verification.PrimaryFingerprint != signer.Fingerprint || report.Scanner == nil || report.Scanner.Result.Verdict != "clean" || report.Scanner.Result.SHA256 != file.SHA256 {
				t.Fatal("combined structured report omitted exact format,signer or scanner binding")
			}
			if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
				t.Fatal("combined checks bypassed separate release", err)
			}
			if _, err = s.Release(f.ctx, f.scope, file.ID, "json-both-release", releaseDecision(current)); err != nil {
				t.Fatal(err)
			}
			_, reader, err := s.Custody.OpenPathReader(f.ctx, f.scope, target)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			got := make([]byte, len(source))
			if n, err := reader.ReadAt(got, 0); n != len(got) || err != nil && err != io.EOF || !bytes.Equal(got, source) {
				t.Fatal("independent combined-check receiver bytes differ", err)
			}
			if _, err = s.RevokePGPKey(f.ctx, f.scope, signer.ID, signer.Version, "json-signer-revoke", workflow.Decision{Hash: signer.Hash, Revision: signer.Revision}); err != nil {
				t.Fatal(err)
			}
			if _, err = reader.ReadAt(make([]byte, 1), 0); !errors.Is(err, store.ErrState) {
				t.Fatal("open structured reader ignored current signer revocation", err)
			}
		})
	}
}
