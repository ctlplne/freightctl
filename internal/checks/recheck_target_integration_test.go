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

func TestRecheckHeldReplacementRefusesEqualRevisionChangedIdentityAndAllowsExactRelease(t *testing.T) {
	f := setup(t)
	s, _, source := policyAndFile(t, f, goodCSV, true)
	checkRelease := func(id, key string) {
		t.Helper()
		if _, err := s.Run(f.ctx, f.scope, id, key+"-check"); err != nil {
			t.Fatal(err)
		}
		c := getCheck(t, s, f, id)
		if c.State != "passed" {
			t.Fatal("exact recheck fixture did not pass")
		}
		if _, err := s.Release(f.ctx, f.scope, id, key+"-release", releaseDecision(c)); err != nil {
			t.Fatal(err)
		}
	}
	checkRelease(source.ID, "source")
	other, _, err := s.Custody.AcceptAt(f.ctx, f.scope, "other-equal-content", int64(len(goodCSV)), secure.Digest([]byte(goodCSV)), strings.NewReader(goodCSV), custody.UploadTarget{Path: "/other.csv"})
	if err != nil {
		t.Fatal(err)
	}
	checkRelease(other.ID, "other")
	copyFor := func(file store.File, path, key string) string {
		t.Helper()
		v, err := s.PreviewRecheck(f.ctx, f.scope, file.ID, RecheckOptions{TargetPath: path, SignatureMode: "not_required", Reason: "Refresh checks with an exact pending replacement guard"})
		if err != nil || v.Plan.Target == nil || v.Plan.Target.Command.ExpectedFileID != file.ID {
			t.Fatal("preview lost exact old custody identity", err)
		}
		var legacy RecheckPlan
		clone, err := json.Marshal(v.Plan)
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(clone, &legacy) != nil {
			t.Fatal("invalid legacy plan fixture")
		}
		legacy.Target.Command.ExpectedFileID = ""
		if _, err = s.ProposeRecheck(f.ctx, f.scope, key+"-unguarded", legacy); !errors.Is(err, store.ErrRevision) {
			t.Fatal("missing exact identity bypassed fresh review", err)
		}
		proposed, err := s.ProposeRecheck(f.ctx, f.scope, key+"-propose", v.Plan)
		if err != nil {
			t.Fatal(err)
		}
		r := recheckRow(t, proposed)
		if _, err = s.DecideRecheck(f.ctx, f.scope, r.ID, key+"-approve", PolicyRecheckDecision{Operation: "approve", Hash: r.Hash, Revision: r.Revision}); err != nil {
			t.Fatal(err)
		}
		result, err := s.CopyRecheck(f.ctx, f.scope, r.ID, key+"-copy")
		if err != nil {
			t.Fatal(err)
		}
		child := recheckRow(t, result).FileID
		c := getCheck(t, s, f, child)
		var b store.CheckBinding
		if json.Unmarshal(c.Binding, &b) != nil || b.Target == nil || b.Target.ExpectedFileID != file.ID || c.State != "held" {
			t.Fatal("held child lost its reviewed old identity")
		}
		return child
	}
	child := copyFor(*source, "/checked.csv", "stale")
	if _, err = s.Run(f.ctx, f.scope, child, "child-check"); err != nil {
		t.Fatal(err)
	}
	checked := getCheck(t, s, f, child)
	if checked.State != "passed" {
		t.Fatal("held recheck did not pass before mapping drift")
	}
	before, err := s.Custody.StatPath(f.ctx, f.scope, "/checked.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "remove-original", store.PathCommand{Operation: "remove", Path: "/checked.csv", ExpectedRevision: &before.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Custody.PathCommand(f.ctx, f.scope, "publish-other", store.PathCommand{Operation: "publish", Path: "/checked.csv", FileID: other.ID}); err != nil {
		t.Fatal(err)
	}
	current, err := s.Custody.StatPath(f.ctx, f.scope, "/checked.csv")
	if err != nil || current.Revision != before.Revision || current.FileID != other.ID || current.ID == before.ID {
		t.Fatal("fixture did not reproduce a new identity at an equal path revision", err)
	}
	if _, err = s.Release(f.ctx, f.scope, child, "refuse-stale-release", releaseDecision(checked)); !errors.Is(err, store.ErrRevision) {
		t.Fatal("stale held recheck overwrote an equal-revision different file", err)
	}
	after := getCheck(t, s, f, child)
	if after.State != "passed" || after.Revision != checked.Revision || after.ReportHash != checked.ReportHash {
		t.Fatal("refused publication changed exact check evidence")
	}
	file, reader, err := s.Custody.DownloadPath(f.ctx, f.scope, "/checked.csv")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || file.ID != other.ID || !bytes.Equal(actual, []byte(goodCSV)) {
		t.Fatal("refused stale release changed current custody or bytes", err)
	}
	positive := copyFor(*other, "/other.csv", "positive")
	checkRelease(positive, "positive-child")
	entry, err := s.Custody.StatPath(f.ctx, f.scope, "/other.csv")
	if err != nil || entry.FileID != positive || entry.Revision != 2 {
		t.Fatal("unchanged exact target did not accept separately checked release", err)
	}
	tx, err := s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(f.ctx)
	var intents, runs int
	if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`).Scan(&intents, &runs); err != nil || intents != 0 || runs != 0 {
		t.Fatal("recheck granted an external or execution effect", err)
	}
}
