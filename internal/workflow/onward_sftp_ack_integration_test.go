//go:build integration && (linux || darwin)

package workflow

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
)

func TestStockSFTPOnwardLostPublicationReplyReconcilesReadOnly(t *testing.T) {
	binary := routingKeyCLI(t)
	f := setup(t)
	remote, marker := stockSFTPReplyLossReceiver(t, f)
	prepared := prepareStockOnward(t, f, remote)
	recovery := prepared.request
	client := collectedExchangeStockClient(t, f, binary)
	agentHTTP := client.curl(prepared.token)
	work := stockOnwardAction{Start: recovery.Start, ReceiptKey: recovery.ReceiptKey, RunID: recovery.RunID}
	const workKey = "work-with-stock-ack-loss"
	worked := readStockExchangeJSON[stockOnwardWorkResult](t, agentHTTP("/onward/work", workKey, work, 200))
	if worked.RunID != recovery.RunID || worked.SelectedDeliveryID != recovery.DeliveryID || worked.ObservedState != "attention" ||
		worked.Replayed || worked.Artifact != recovery.Start.Request.Artifact || len(worked.Steps) != 1 || worked.Steps[0].State != "ambiguous" || remote.sessions(t) != 1 {
		t.Fatal("a lost stock hardlink acknowledgment did not leave the exact delivery ambiguous")
	}
	ack, err := os.ReadFile(marker)
	if err != nil || !hashPattern.MatchString(strings.TrimSuffix(string(ack), "\n")) {
		t.Fatal("the independent server did not produce a matching successful hardlink response", err)
	}
	final := filepath.Join(remote.directory, recovery.DeliveryID+"-"+stockOnwardFilename)
	stage := filepath.Join(remote.directory, ".freightctl-"+recovery.DeliveryID+"-1.partial")
	original, err := os.Stat(final)
	if err != nil {
		t.Fatal("the independent server did not publish after sending the lost reply", err)
	}
	staged, err := os.Stat(stage)
	if err != nil || !os.SameFile(original, staged) {
		t.Fatal("final and retained stage do not point to the original published bytes", err)
	}
	sender := &delivery.Service{Custody: f.s.Custody}
	uncertain, err := sender.Status(f.ctx, prepared.scope, recovery.DeliveryID)
	if err != nil || uncertain.State != "ambiguous" || uncertain.Fence != 1 || uncertain.Attempts != 1 || uncertain.LeaseUntil != nil {
		t.Fatal("lost acknowledgment incorrectly changed the original attempt or lease", err)
	}
	agentHTTP("/onward/work", workKey, work, 409)
	agentHTTP("/onward/work", "a-second-work-key", work, 409)
	client.curl(f.tokenPath)("/onward/reconcile", "operator-foreign-intent", recovery, 404)
	if remote.sessions(t) != 1 {
		t.Fatal("work or a different actor attempted to contact the receiver after ambiguity")
	}

	const reconcileKey = "check-only-after-stock-ack-loss"
	result := readStockExchangeJSON[OnwardReconciliation](t, agentHTTP("/onward/reconcile", reconcileKey, recovery, 200))
	if result.RunID != recovery.RunID || result.DeliveryID != recovery.DeliveryID || result.DeliveryState != "succeeded" ||
		result.Observation != "integrity-observed" || result.Replayed || result.ReceiverPersistence != "unknown" || result.BusinessProcessing != "unknown" || remote.sessions(t) != 2 {
		t.Fatal("an approved read-only session did not resolve the exact published content")
	}
	result.Replayed = true
	if replay := readStockExchangeJSON[OnwardReconciliation](t, agentHTTP("/onward/reconcile", reconcileKey, recovery, 200)); replay != result || remote.sessions(t) != 2 {
		t.Fatal("reconciliation replay contacted the receiver or changed the original receipt")
	}
	confirmed, err := sender.Status(f.ctx, prepared.scope, recovery.DeliveryID)
	var observation struct {
		SHA256 string `json:"sha256"`
		Fsync  bool   `json:"file_fsync_acknowledged"`
	}
	if err != nil || confirmed.Fence != 1 || confirmed.Attempts != 1 || confirmed.State != "succeeded" ||
		json.Unmarshal(confirmed.Observation, &observation) != nil || observation.Fsync || observation.SHA256 != recovery.Start.Request.Artifact.SHA256 {
		t.Fatal("readback invented another attempt or a file sync acknowledgment", err)
	}
	view, err := f.s.Status(f.ctx, prepared.scope, recovery.RunID)
	if err != nil || view.Run.State != "succeeded" || view.ObservedState != "succeeded" {
		t.Fatal("matching stock read did not settle the exact workflow projection", err)
	}
	remote.requireBytes(t, f, filepath.Base(final))
	assertStockPeerReadOnly(t, f, remote, final)
	current, err := os.Stat(final)
	if err != nil || !os.SameFile(original, current) || !current.ModTime().Equal(original.ModTime()) || current.Mode() != original.Mode() {
		t.Fatal("read-only recovery replaced or changed the original final file", err)
	}
	held, err := os.Stat(stage)
	if err != nil || !os.SameFile(original, held) || remote.sessions(t) != 4 {
		t.Fatal("readback changed the retained stage or the expected session count", err)
	}
	t.Log("stock hardlink acknowledgment dropped after successful publication; replay sent nothing; read-only recovery retained one attempt and fence")
}

func stockSFTPReplyLossReceiver(t *testing.T, f *fixture) (*mixedStockReceiver, string) {
	t.Helper()
	stock := "/usr/lib/openssh/sftp-server"
	if runtime.GOOS == "darwin" {
		stock = "/usr/libexec/sftp-server"
	}
	if info, err := os.Stat(stock); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatal("stock OpenSSH SFTP server unavailable", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../../scripts/peers/stock-sftp-publication-reply.py")
	if err != nil {
		t.Fatal(err)
	}
	var marker string
	remote := startStockSFTPPeer(t, f, false, func(directory string) string {
		marker = filepath.Join(filepath.Dir(directory), "stock-hardlink-ack.sha256")
		args := []string{python, script, stock, directory, marker}
		for index, arg := range args {
			args[index] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}
		return strings.Join(args, " ")
	})
	return remote, marker
}

func assertStockPeerReadOnly(t *testing.T, f *fixture, remote *mixedStockReceiver, final string) {
	t.Helper()
	batch := filepath.Join(filepath.Dir(remote.directory), "verify-readonly.batch")
	violation := filepath.Join(remote.directory, "unexpected-sftp-write.csv")
	line := "put " + strconv.Quote(final) + " " + strconv.Quote(violation) + "\n"
	if err := os.WriteFile(batch, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(f.ctx, "sftp", remote.sftpArgs(batch)...).CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("Permission denied")) {
		t.Fatalf("stock receiver accepted a recovery-session write; output_sha256=%s", secure.Digest(output))
	}
	if _, err := os.Stat(violation); !os.IsNotExist(err) {
		t.Fatal("the independent read-only server created a new file", err)
	}
}
