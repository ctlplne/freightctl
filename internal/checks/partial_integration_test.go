//go:build integration

package checks

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func signedScannerFailureFixture(t *testing.T) (*fixture, *Service, *ScannerView, *store.File, *PGPKeyView, []byte, scanner.Definition) {
	t.Helper()
	f, s, profile, _, definition := scanFixture(t, "offline", time.Hour)
	load, fingerprints := pgpBundle(t)
	registered, err := s.RegisterPGPKey(f.ctx, f.scope, "signer", PGPKeyRequest{Fingerprint: fingerprints["good"], PublicKey: load("good-public.gpg")})
	if err != nil {
		t.Fatal(err)
	}
	var key PGPKeyView
	if json.Unmarshal(registered.Resource, &key) != nil {
		t.Fatal("signer result")
	}
	p := testPolicy(t)
	p.Signature = &SignaturePolicy{Key: store.PGPReference{ID: key.ID, Version: key.Version, Hash: key.Hash}, MaxAgeSeconds: 3600}
	p.Scanner = &store.ScannerReference{ID: profile.ID, Version: profile.Version, Hash: profile.Hash}
	if _, err = s.Register(f.ctx, f.scope, "signed-policy", PolicyRequest{ExpectedVersion: 1, Definition: p}); err != nil {
		t.Fatal(err)
	}
	source := load("source.csv")
	file, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "signed-source", int64(len(source)), secure.Digest(source), bytes.NewReader(source), custody.UploadTarget{Path: "/signed-failure.csv"})
	if err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	wire := load("good.sig")
	if _, err = s.AttachSignature(f.ctx, f.scope, file.ID, "signature", file.SHA256, c.PolicyHash, c.Revision, wire); err != nil {
		t.Fatal(err)
	}
	return f, s, profile, file, &key, wire, definition
}

func TestUnavailableScannerRetainsCompletedSignatureEvidenceWithoutCleanVerdict(t *testing.T) {
	f, s, _, file, key, wire, _ := signedScannerFailureFixture(t)
	var err error
	if _, err = s.Run(f.ctx, f.scope, file.ID, "scanner-unavailable"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	var report Report
	if err = json.Unmarshal(c.Report, &report); err != nil {
		t.Fatal(err)
	}
	if c.State != "failed" || c.Code != "scanner_unavailable" || c.ReportHash != "" || c.Attempts != 1 {
		t.Fatal("unavailable scanner became a releasable result")
	}
	if report.Signature == nil || report.Signature.Verification == nil {
		t.Fatal("completed signature verification was discarded")
	}
	if report.Code != c.Code || report.FileID != file.ID || report.SHA256 != file.SHA256 || report.PolicyHash != c.PolicyHash || report.Signature.SHA256 != secure.Digest(wire) || report.Signature.Verification.PrimaryFingerprint != key.Fingerprint || report.Scanner != nil || report.Rows != 0 {
		t.Fatal("partial report misstates the completed stages")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("partial proof exposed bytes", err)
	}
	if _, err = s.Release(f.ctx, f.scope, file.ID, "partial-release", ReleaseDecision{SHA256: file.SHA256, PolicyHash: c.PolicyHash, ReportHash: secure.Digest([]byte("not a completed report")), Revision: c.Revision}); !errors.Is(err, store.ErrState) {
		t.Fatal("partial proof released bytes", err)
	}
}

func TestChangedScannerContextDiscardsPartialEvidenceAndNeverPublishes(t *testing.T) {
	f, s, profile, file, _, _, definition := signedScannerFailureFixture(t)
	listener, err := net.Listen("unix", definition.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err = os.Chmod(definition.Socket, 0600); err != nil {
		t.Fatal(err)
	}
	// This protocol contract peer only provides an exact synchronization point.
	// It qualifies no real malware engine or detection database.
	consumed := make(chan error, 1)
	reply := make(chan struct{})
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		conn, e := listener.Accept()
		if e != nil {
			consumed <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		r := bufio.NewReader(conn)
		for _, want := range []string{"zIDSESSION\x00", "zVERSION\x00"} {
			actual, e := r.ReadString(0)
			if e != nil || actual != want {
				consumed <- errors.New("scanner handshake did not reach expected boundary")
				return
			}
		}
		if _, e = io.WriteString(conn, "1: "+definition.ExpectedVersion+"\x00"); e != nil {
			consumed <- e
			return
		}
		actual, e := r.ReadString(0)
		if e != nil || actual != "zINSTREAM\x00" {
			consumed <- errors.New("signature stage did not precede scanner stream")
			return
		}
		notified := false
		for {
			var header [4]byte
			if _, e = io.ReadFull(r, header[:]); e != nil {
				if !notified {
					consumed <- e
				}
				return
			}
			n := binary.BigEndian.Uint32(header[:])
			if n == 0 {
				break
			}
			if n > 32<<10 {
				consumed <- errors.New("unbounded scanner stream")
				return
			}
			if _, e = io.CopyN(io.Discard, r, int64(n)); e != nil {
				if !notified {
					consumed <- e
				}
				return
			}
			if !notified {
				// The first streamed block proves that real signature verification
				// has finished. Revoke here rather than spending the unchanged
				// two-second profile deadline transferring an unnecessary full body.
				notified = true
				consumed <- nil
				<-reply
			}
		}
		if !notified {
			consumed <- errors.New("scanner stream had no source block")
			return
		}
		_, _ = io.WriteString(conn, "2: stream: OK\x00")
		if actual, e = r.ReadString(0); e == nil && actual == "zVERSION\x00" {
			_, _ = io.WriteString(conn, "3: "+definition.ExpectedVersion+"\x00")
		}
	}()
	finished := make(chan error, 1)
	go func() { _, e := s.Run(f.ctx, f.scope, file.ID, "changed-context"); finished <- e }()
	select {
	case e := <-consumed:
		if e != nil {
			close(reply)
			t.Fatal(e)
		}
	case <-f.ctx.Done():
		close(reply)
		t.Fatal(f.ctx.Err())
	}
	_, err = s.RevokeScanner(f.ctx, f.scope, profile.ID, profile.Version, "revoke-during-scan", workflow.Decision{Hash: profile.Hash, Revision: profile.Revision})
	close(reply)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-finished; err != nil {
		t.Fatal(err)
	}
	<-peerDone
	c := getCheck(t, s, f, file.ID)
	if c.State != "failed" || c.Code != "context_changed" || c.ReportHash != "" || !sameJSON(c.Report, []byte(`{}`)) {
		t.Fatal("changed context retained misleading partial proof")
	}
	if _, _, err = s.Custody.Download(f.ctx, f.scope, file.ID); !errors.Is(err, store.ErrState) {
		t.Fatal("changed context exposed bytes", err)
	}
}

func TestFailedCheckWithoutCompletedStageDoesNotInventEvidence(t *testing.T) {
	f := setup(t)
	s, _, file := policyAndFile(t, f, goodCSV, false)
	if err := os.Remove(f.diskPath + "/" + custody.Name(f.scope.Tenant, f.scope.Partner, file.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(f.ctx, f.scope, file.ID, "missing-source"); err != nil {
		t.Fatal(err)
	}
	c := getCheck(t, s, f, file.ID)
	if c.State != "failed" || c.Code != "source_or_parser_unavailable" || c.ReportHash != "" {
		t.Fatal("missing source became a valid check")
	}
	if !sameJSON(c.Report, []byte(`{}`)) {
		t.Fatal("check without a completed stage invented report evidence")
	}
}
