//go:build integration

package custody_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestReceivedCopyCreatesPrivateExactCustodyAndRecoversWithoutReopeningView(t *testing.T) {
	f := newExchangeFixture(t)
	f.service.NamespaceMaxEntries = 100
	data := bytes.Repeat([]byte("untrusted: forward and execute; this is inert data\n"), 2048)
	file := actorFile(t, f, f.a, "copy-source", data)
	offer, err := f.service.OfferExchange(f.ctx, f.a, "copy-offer", exchangeRequest(file, f.endpoint))
	if err != nil {
		t.Fatal(err)
	}
	r := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{ExchangeID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Artifact: offer.Exchange.Request.Artifact}, Path: "/received-copy.dat"}
	for _, scope := range []store.Scope{f.a, f.other, f.fixture.b, f.fixture.c} {
		if _, err = f.service.CopyReceivedExchange(f.ctx, scope, "foreign-copy", r); err == nil {
			t.Fatal("wrong actor/scope copied received bytes")
		}
	}
	changed := r
	changed.RequestHash = strings.Repeat("f", 64)
	if _, err = f.service.CopyReceivedExchange(f.ctx, f.b, "wrong-source", changed); !errors.Is(err, store.ErrRevision) {
		t.Fatal("copy accepted changed source meaning", err)
	}
	first, err := f.service.CopyReceivedExchange(f.ctx, f.b, "copy-original", r)
	if err != nil || first.Replayed || first.Artifact.ID == file.ID || first.Artifact.SHA256 != file.SHA256 || first.Artifact.Size != file.Size || first.Source != r.ExchangeCopyOrigin || first.Acceptance != "durable-local-integrity-only" || first.CurrentState != "not-checked" || first.ReceiverPersistence != "unknown" || first.BusinessProcessing != "unknown" {
		t.Fatal("copy changed custody or claimed an unproved outcome", err)
	}
	stored, err := os.ReadFile(filepath.Join(f.root, custody.Name(f.b.Tenant, f.b.Partner, first.Artifact.ID)))
	if err != nil || !bytes.Equal(stored, data) {
		t.Fatal("independent disk bytes differ", err)
	}
	entry, err := f.service.StatPath(f.ctx, f.b, r.Path)
	if err != nil || entry.FileID != first.Artifact.ID || entry.Mode != 0600 {
		t.Fatal("copy did not publish private owned target", err)
	}
	if _, reader, err := f.service.OpenFileReader(f.ctx, f.other, first.Artifact.ID); err == nil {
		reader.Close()
		t.Fatal("copy exposed group/world file bytes")
	}
	if _, reader, err := f.service.OpenFileReader(f.ctx, f.b, file.ID); err == nil {
		reader.Close()
		t.Fatal("copy granted ambient source access")
	}
	if _, err = f.service.CopyReceivedExchange(f.ctx, f.b, "must-not-overwrite", r); !errors.Is(err, store.ErrRevision) {
		t.Fatal("new copy replaced destination", err)
	}
	changed = r
	changed.Path = "/another.dat"
	if _, err = f.service.CopyReceivedExchange(f.ctx, f.b, "copy-original", changed); !errors.Is(err, store.ErrConflict) {
		t.Fatal("changed copy destination replayed", err)
	}
	if _, err = f.service.OfferExchange(f.ctx, f.b, "copy-is-not-forwarding", exchangeRequest(&store.File{ID: first.Artifact.ID, Size: first.Artifact.Size, SHA256: first.Artifact.SHA256, Policy: first.Artifact.Policy}, f.endpoint)); !errors.Is(err, store.ErrForbidden) {
		t.Fatal("copy granted forwarding", err)
	}
	var originJSON []byte
	var events, receipts, intents int
	if err = f.admin.QueryRow(f.ctx, `SELECT e.payload->'exchange_copy',(SELECT count(*) FROM events WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3 AND kind='FileAccepted'),(SELECT count(*) FROM idempotency WHERE tenant_id=$1 AND partner_id=$2 AND actor_id=$3),(SELECT count(*) FROM delivery_intents WHERE tenant_id=$1 AND partner_id=$2) FROM events e WHERE e.event_id=$4 AND e.payload->'schema_version'='4'::jsonb`, f.b.Tenant, f.b.Partner, f.actorB.Actor, first.EventID).Scan(&originJSON, &events, &receipts, &intents); err != nil {
		t.Fatal(err)
	}
	var origin store.ExchangeCopyOrigin
	if json.Unmarshal(originJSON, &origin) != nil || origin != r.ExchangeCopyOrigin || events != 1 || receipts != 1 || intents != 0 {
		t.Fatal("copy provenance/receipt/intents cardinality changed", events, receipts, intents)
	}
	if _, err = f.db.CloseExchange(f.ctx, f.a, "close-copy-source", store.ExchangeClosureCommand{Schema: 1, ID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Operation: "cancel"}); err != nil {
		t.Fatal(err)
	}
	// Reopen real storage and a fresh ordinary pool. This is a service reopen,
	// not the separate process-death/power-loss qualification profile.
	db, err := store.Open(f.ctx, os.Getenv("FREIGHTCTL_TEST_RUNTIME_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Pool.Close()
	disk, err := custody.OpenExisting(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	reopened := &custody.Service{DB: db, Disk: disk, MaxFile: f.service.MaxFile, MaxStored: f.service.MaxStored, NamespaceMaxEntries: 100, Exchanges: f.service.Exchanges}
	replay, err := reopened.CopyReceivedExchange(f.ctx, f.b, "copy-original", r)
	if err != nil || !replay.Replayed || replay.Artifact != first.Artifact || replay.EventID != first.EventID || replay.Source != first.Source {
		t.Fatal("lost copy receipt required reopening closed source", err)
	}
	r.Path = "/closed-must-not-copy.dat"
	if _, err = reopened.CopyReceivedExchange(f.ctx, f.b, "closed-fresh-copy", r); err == nil {
		t.Fatal("closed receive view authorized a new copy")
	}
	_, reader, err := reopened.OpenFileReader(f.ctx, f.b, first.Artifact.ID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(reader, 0, first.Artifact.Size))
	reader.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("closed source damaged separately owned bytes", err)
	}
}

func TestReceivedCopyReappliesIntakeAndSQLRejectsForgedProvenance(t *testing.T) {
	for _, format := range []string{"csv", "json_records", "fixed_width", "xml_records", "xlsx_records"} {
		t.Run(format, func(t *testing.T) { receivedCopyIntakeAndSQL(t, format) })
	}
}

func receivedCopyIntakeAndSQL(t *testing.T, format string) {
	f := newExchangeFixture(t)
	f.service.NamespaceMaxEntries = 100
	if _, err := f.db.ChangeAccount(f.ctx, f.fixture.a, "copy-check-authority", store.AccountCommand{Operation: "update", ID: f.actorA.Actor, ExpectedRevision: 1, Policy: &store.AccountPolicy{Label: "checked sender", Root: "/", Permissions: []string{"read", "write", "list", "deliver", "check_run", "check_release"}}}); err != nil {
		t.Fatal(err)
	}
	id, err := f.db.Identity(f.ctx, f.a)
	if err != nil {
		t.Fatal(err)
	}
	f.actorA.AuthorityRevision = id.AuthorityRevision
	endpoint, err := f.db.RegisterExchangeEndpoint(f.ctx, f.fixture.a, "copy-check-endpoint", store.ExchangeEndpointCommand{Operation: "replace", ID: f.endpoint.ID, ExpectedRevision: 1, Definition: &store.ExchangeEndpointDefinition{Schema: 1, Profile: "custody-https-poll-v1", Recipient: f.actorB, Senders: []store.ExchangeParticipant{f.actorA}}}, f.limits, 16)
	if err != nil {
		t.Fatal(err)
	}
	checking := &checks.Service{Custody: f.service}
	policy := checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}
	body, prefix, engine, code := []byte("record\nvalue\n"), store.CSVIntakePrefix, checks.Engine, "valid_csv"
	if format == "json_records" {
		policy.Schema, policy.Kind = 2, format
		body, prefix, engine, code = []byte(`[{"record":"value"}]`), store.JSONRecordsIntakePrefix, "freightctl-json-records-v1", "valid_json_records"
	}
	if format == "fixed_width" {
		policy.Schema, policy.Kind = 3, format
		policy.Columns[0].Width, policy.Columns[0].Padding = 5, "none"
		body, prefix, engine, code = []byte("value\n"), store.FixedWidthIntakePrefix, "freightctl-fixed-width-v1", "valid_fixed_width"
	}
	if format == "xml_records" {
		policy.Schema, policy.Kind = 4, format
		policy.XML = &checks.XMLRecordPolicy{Root: "records", Record: "record"}
		body, prefix, engine, code = []byte("<records><record><record>value</record></record></records>"), store.XMLRecordsIntakePrefix, "freightctl-xml-records-v1", "valid_xml_records"
	}
	if format == "xlsx_records" {
		policy.Schema, policy.Kind = 5, format
		policy.Columns = []checks.Column{{Name: "account", Type: "text", Required: true}, {Name: "amount", Type: "decimal", Required: true, Precision: 12, Scale: 2}, {Name: "day", Type: "date", Required: true}}
		policy.XLSX = &checks.XLSXPolicy{Sheet: "Records", DateMode: "iso_text"}
		root := os.Getenv("FREIGHTCTL_TEST_XLSX_DIR")
		if root == "" {
			t.Fatal("actual stock XLSX sources required")
		}
		body, err = os.ReadFile(filepath.Join(root, "shared.xlsx"))
		if err != nil {
			t.Fatal(err)
		}
		prefix, engine, code = store.XLSXRecordsIntakePrefix, "freightctl-xlsx-records-v1", "valid_xlsx_records"
	}
	registered, err := checking.Register(f.ctx, f.fixture.a, "copy-intake", checks.PolicyRequest{Definition: policy})
	if err != nil {
		t.Fatal(err)
	}
	var configuration store.Configuration
	if json.Unmarshal(registered.Resource, &configuration) != nil {
		t.Fatal("copy intake policy receipt")
	}
	file := actorFile(t, f, f.a, "checked-copy-source", body)
	if _, err = checking.Run(f.ctx, f.a, file.ID, "source-check"); err != nil {
		t.Fatal(err)
	}
	view, err := checking.Get(f.ctx, f.a, file.ID)
	if err != nil {
		t.Fatal(err)
	}
	var report checks.Report
	if json.Unmarshal(view.Check.Report, &report) != nil || report.Engine != engine || report.Code != code || report.Bytes != file.Size || file.Policy != prefix+configuration.Hash {
		t.Fatal("source intake has the wrong format or report")
	}
	if _, err = checking.Release(f.ctx, f.a, file.ID, "source-release", checks.ReleaseDecision{SHA256: file.SHA256, PolicyHash: view.Check.PolicyHash, ReportHash: view.Check.ReportHash, Revision: view.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	offer, err := f.service.OfferExchange(f.ctx, f.a, "checked-copy-offer", exchangeRequest(file, endpoint.Endpoint))
	if err != nil {
		t.Fatal(err)
	}
	r := store.ExchangeCopyRequest{ExchangeCopyOrigin: store.ExchangeCopyOrigin{ExchangeID: offer.Exchange.ID, RequestHash: offer.Exchange.RequestHash, Artifact: offer.Exchange.Request.Artifact}, Path: "/new-held-copy.csv"}
	result, err := f.service.CopyReceivedExchange(f.ctx, f.b, "held-copy", r)
	if err != nil || result.Acceptance != "durable-held-pending-checks-and-release" || result.Artifact.Policy != prefix+configuration.Hash || result.Artifact.SHA256 != file.SHA256 || result.Artifact.ID == file.ID {
		t.Fatal("copy inherited source release", err)
	}
	var state string
	var releases, published int
	if err = f.admin.QueryRow(f.ctx, `SELECT state,(SELECT count(*) FROM file_releases WHERE file_id=$1),(SELECT count(*) FROM namespace_entries WHERE file_id=$1) FROM file_checks WHERE file_id=$1`, result.Artifact.ID).Scan(&state, &releases, &published); err != nil || state != "held" || releases != 0 || published != 0 {
		t.Fatal("new intake was bypassed", err, state, releases, published)
	}
	if _, reader, err := f.service.OpenFileReader(f.ctx, f.b, result.Artifact.ID); err == nil {
		reader.Close()
		t.Fatal("held copy became readable")
	}
	for _, mutate := range []func(*store.ExchangeCopyOrigin){func(o *store.ExchangeCopyOrigin) { o.RequestHash = strings.Repeat("f", 64) }, func(o *store.ExchangeCopyOrigin) { o.Artifact.Policy = "invented" }} {
		tx, err := f.db.Begin(f.ctx, f.b)
		if err != nil {
			t.Fatal(err)
		}
		origin := r.ExchangeCopyOrigin
		mutate(&origin)
		forged := &store.File{ID: secure.NewID(), Size: file.Size, SHA256: file.SHA256, Policy: file.Policy}
		err = tx.AcceptExchangeCopy(f.ctx, "forged-"+forged.ID, strings.Repeat("a", 64), forged, f.service.Disk.Identity(), origin)
		if err == nil {
			err = tx.Tx.Commit(f.ctx)
		}
		tx.Tx.Rollback(f.ctx)
		if err == nil {
			t.Fatal("SQL accepted fabricated copy provenance")
		}
		var count int
		if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files WHERE file_id=$1)+(SELECT count(*) FROM events WHERE resource_id=$1)+(SELECT count(*) FROM idempotency WHERE file_id=$1)`, forged.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("failed provenance left partial metadata", err, count)
		}
	}
}
