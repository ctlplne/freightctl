//go:build integration

package custody_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestArtifactIngressDescriptorCreatesNoGrantReceiptBytesOrEvent(t *testing.T) {
	f := newExchangeFixture(t)
	storedBytes := func() map[string]string {
		t.Helper()
		entries, err := os.ReadDir(f.root)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > f.service.MaxStored {
				t.Fatal("unexpected fixture storage entry")
			}
			raw, err := os.ReadFile(filepath.Join(f.root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			out[entry.Name()] = secure.Digest(raw) + ":" + info.Mode().String()
		}
		return out
	}
	bytesBefore := storedBytes()
	snapshot := func() [5]int {
		t.Helper()
		tx, err := f.db.Begin(f.ctx, f.a)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(f.ctx)
		var c [5]int
		if err = tx.Tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM idempotency),(SELECT count(*) FROM events),(SELECT count(*) FROM artifact_exchanges),(SELECT count(*) FROM delivery_intents)`).Scan(&c[0], &c[1], &c[2], &c[3], &c[4]); err != nil {
			t.Fatal(err)
		}
		return c
	}
	request := custody.IngressDescriptorRequest{Size: 3, SHA256: secure.Digest([]byte("abc")), Key: "descriptor-original-upload"}
	before := snapshot()
	for range 3 {
		d, err := f.service.PrepareArtifactIngress(f.ctx, f.a, request)
		if err != nil || d.Request != request || d.Method != "POST" || d.Path != "/v1/tenants/"+f.a.Tenant+"/partners/"+f.a.Partner+"/files" || d.State != "metadata-only" || d.Availability != "not-checked" || d.AcceptancePolicy != "evaluated-by-upload-service" || d.ReceiverPersistence != "unknown" {
			t.Fatal("descriptor altered meaning or claimed an outcome", err)
		}
		if len(d.Headers) != 4 || d.Headers["X-File-Size"] != "3" || d.Headers["X-Content-SHA256"] != request.SHA256 || d.Headers["Idempotency-Key"] != request.Key || d.Headers["Content-Type"] != "application/octet-stream" {
			t.Fatal("descriptor changed actual upload header meaning")
		}
		raw, _ := json.Marshal(d)
		if strings.Contains(string(raw), f.a.TokenHash) || strings.Contains(string(raw), "Authorization") || strings.Contains(string(raw), "Bearer ") {
			t.Fatal("descriptor disclosed credential material")
		}
	}
	if snapshot() != before {
		t.Fatal("metadata descriptor created durable effects")
	}
	if !reflect.DeepEqual(bytesBefore, storedBytes()) {
		t.Fatal("metadata descriptor changed actual stored bytes or modes")
	}
	readOnly, _ := exchangeActor(t, f.fixture, []string{"read", "list"})
	if _, err := f.service.PrepareArtifactIngress(f.ctx, readOnly, request); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("receiving supplied upload authority", err)
	}
	file, replayed, err := f.service.Accept(f.ctx, f.a, request.Key, request.Size, request.SHA256, bytes.NewReader([]byte("abc")))
	if err != nil || replayed || file.Size != request.Size || file.SHA256 != request.SHA256 {
		t.Fatal("descriptor consumed actual admission or altered bytes", err)
	}
	again, replayed, err := f.service.Accept(f.ctx, f.a, request.Key, request.Size, request.SHA256, bytes.NewReader([]byte("abc")))
	if err != nil || !replayed || again.ID != file.ID {
		t.Fatal("original upload key lost accepted source identity", err)
	}
}
