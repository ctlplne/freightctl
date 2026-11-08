//go:build integration && davpeer

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/workflow"
)

func TestDAVCollectionNativeReviewedAPIReadOnlySourceAndOriginalReceipt(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Fatal("served DAV collection requires its authorized native Actions environment")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	commit := strings.TrimSpace(string(commitRaw))
	if err != nil || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" || commit != os.Getenv("GITHUB_SHA") {
		t.Fatal("served DAV source differs from the actual native candidate")
	}
	producer, producerScope, producerToken, producerHTTP := browserAPI(t, 10*time.Minute)
	consumer, consumerScope, consumerToken, consumerHTTP := browserAPI(t, 10*time.Minute)
	producerPrefix := "/v1/tenants/" + producerScope.Tenant + "/partners/" + producerScope.Partner
	consumerPrefix := "/v1/tenants/" + consumerScope.Tenant + "/partners/" + consumerScope.Partner
	producerCookie, producerCSRF := loginBrowser(t, producerHTTP, producerScope, producerToken)
	sourceCredential, sourceParticipant := exchangeAPIParticipant(t, producerHTTP, producerPrefix, producerCookie, producerCSRF, []string{"read", "list"})
	for _, fixture := range []struct {
		service *custody.Service
		scope   store.Scope
	}{{producer, producerScope}, {consumer, consumerScope}} {
		if _, err = fixture.service.PathCommand(t.Context(), fixture.scope, "dav-collection-directory", store.PathCommand{Operation: "mkdir", Path: "/inbox"}); err != nil {
			t.Fatal(err)
		}
	}
	data := bytes.Repeat([]byte("inert cross-system artifact; source grants no onward authority\n"), 2000)
	file, _, err := producer.AcceptAt(t.Context(), producerScope, "dav-collection-producer-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/inbox/input.dat"})
	if err != nil {
		t.Fatal(err)
	}
	manifest := exchangeAPIJSON(t, workflow.CollectionManifest{Schema: 1, Batch: secure.NewID(), Files: []workflow.CollectionFile{{Name: "input.dat", Size: int64(len(data)), SHA256: secure.Digest(data)}}})
	ready, _, err := producer.AcceptAt(t.Context(), producerScope, "dav-collection-producer-ready-last", int64(len(manifest)), secure.Digest(manifest), bytes.NewReader(manifest), custody.UploadTarget{Path: "/inbox/batch.ready.json"})
	if err != nil {
		t.Fatal(err)
	}
	count := func(service *custody.Service, scope store.Scope) [5]int {
		t.Helper()
		tx, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(t.Context())
		var n [5]int
		if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM files),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM events),(SELECT count(*) FROM workflow_receipts)`).Scan(&n[0], &n[1], &n[2], &n[3], &n[4]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	producerBefore := count(producer, producerScope)
	producerActor := ""
	snapshotProducer := func() (string, map[string]davSourceAuditRow) {
		t.Helper()
		tx, err := producer.DB.Begin(t.Context(), producerScope)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Tx.Rollback(t.Context())
		if producerActor == "" {
			producerActor = tx.Actor
		} else if producerActor != tx.Actor {
			t.Fatal("producer snapshot actor changed")
		}
		var state []byte
		if err = tx.Tx.QueryRow(t.Context(), `SELECT jsonb_build_object(
'files',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY file_id),'[]'::jsonb) FROM files x),
'entries',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY entry_id),'[]'::jsonb) FROM namespace_entries x),
'revisions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY entry_id,revision),'[]'::jsonb) FROM namespace_revisions x),
'commands',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY actor_id,request_key),'[]'::jsonb) FROM namespace_commands x),
'credentials',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY actor_id),'[]'::jsonb) FROM credentials x),
'deliveries',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY delivery_id),'[]'::jsonb) FROM delivery_intents x),
'runs',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY run_id),'[]'::jsonb) FROM workflow_runs x),
'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY actor_id,request_key),'[]'::jsonb) FROM workflow_receipts x))`).Scan(&state); err != nil {
			t.Fatal("producer state snapshot failed", err)
		}
		rows, err := tx.Tx.Query(t.Context(), `SELECT event_id::text,actor_id::text,kind,resource_id::text,payload,to_jsonb(events)::text FROM events ORDER BY happened_at,event_id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		events := map[string]davSourceAuditRow{}
		for rows.Next() {
			var id, raw string
			var e davSourceAuditRow
			if err = rows.Scan(&id, &e.Actor, &e.Kind, &e.Resource, &e.Payload, &raw); err != nil {
				t.Fatal(err)
			}
			e.Hash = secure.Digest([]byte(raw))
			events[id] = e
		}
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
		return secure.Digest(state), events
	}
	producerState, producerEvents := snapshotProducer()
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	ca, err := secure.NativeProofCertificatePEM(producerHTTP.Certificate().Raw)
	if err != nil {
		t.Fatal(err)
	}
	caRef, tokenRef := filepath.Join(private, "producer-ca.pem"), filepath.Join(private, "producer-token")
	for name, body := range map[string][]byte{caRef: ca, tokenRef: sourceCredential.Bytes} {
		if err = os.WriteFile(name, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	engine := &workflow.Service{Custody: consumer}
	registered, err := engine.RegisterConnection(t.Context(), consumerScope, "dav-collection-register", workflow.ConnectionRequest{Directory: producerPrefix + "/dav/inbox", DAV: &delivery.DAVCollectionSource{Schema: 1, Destination: secure.HTTPSReadDestination{Address: strings.TrimPrefix(producerHTTP.URL, "https://"), ServerName: "example.com", CAFile: caRef, CASHA256: secure.Digest(ca), TokenFile: tokenRef, TokenSHA256: secure.Digest(sourceCredential.Bytes)}}})
	if err != nil {
		t.Fatal("ordinary reviewed DAV source registration failed", err)
	}
	var connection workflow.ConnectionView
	if json.Unmarshal(registered.Resource, &connection) != nil || connection.DAV == nil || !connection.DAV.ReadOnly || connection.Protocol != "webdav" {
		t.Fatal("DAV registration lost exact read-only metadata")
	}
	guard, err := consumer.DB.Begin(t.Context(), consumerScope)
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := guard.Configuration(t.Context(), true, connection.ID, connection.Version, false)
	if err != nil {
		guard.Tx.Rollback(t.Context())
		t.Fatal(err)
	}
	var shape bool
	if err = guard.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_collection_connection($1::jsonb)`, configuration.Definition).Scan(&shape); err != nil || !shape {
		guard.Tx.Rollback(t.Context())
		t.Fatal("actual runtime SQL refused the exact DAV connection shape", err)
	}
	for _, change := range []func(map[string]any){
		func(d map[string]any) { d["schema_version"] = 1 },
		func(d map[string]any) { d["directory"] = "/inbox/../private" },
		func(d map[string]any) { d["destination"].(map[string]any)["address"] = "127.0.0.1:22" },
		func(d map[string]any) {
			d["dav"].(map[string]any)["destination"].(map[string]any)["token_sha256"] = "invalid"
		},
		func(d map[string]any) {
			d["dav"].(map[string]any)["destination"].(map[string]any)["address"] = "https://outside.invalid/"
		},
	} {
		var altered map[string]any
		if json.Unmarshal(configuration.Definition, &altered) != nil {
			t.Fatal("stored DAV definition invalid")
		}
		change(altered)
		if err = guard.Tx.QueryRow(t.Context(), `SELECT freightctl_dav_collection_connection($1::jsonb)`, exchangeAPIJSON(t, altered)).Scan(&shape); err != nil || shape {
			guard.Tx.Rollback(t.Context())
			t.Fatal("actual SQL admitted mixed or changed DAV authority", err)
		}
	}
	guard.Tx.Rollback(t.Context())
	definition := workflow.Definition{Schema: 1, Name: "Reviewed DAV source only", Steps: []workflow.Step{}, Source: &workflow.CollectionSource{Kind: "webdav.collect", Connection: workflow.Reference{ID: connection.ID, Version: connection.Version, Hash: connection.Hash}, Manifest: "batch.ready.json", Directory: "/inbox", Contract: workflow.CollectionContract, MaxFiles: 4, MaxFile: 1 << 20, MaxTotal: 4 << 20}}
	drafted, err := engine.Draft(t.Context(), consumerScope, "dav-collection-draft", workflow.DraftRequest{Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	var declared store.Configuration
	if json.Unmarshal(drafted.Resource, &declared) != nil {
		t.Fatal("DAV workflow draft invalid")
	}
	if _, err = engine.Decide(t.Context(), consumerScope, declared.ID, declared.Version, "dav-collection-approve", "approve", workflow.Decision{Hash: declared.Hash, Revision: declared.Revision}); err != nil {
		t.Fatal(err)
	}
	tx, err := consumer.DB.Begin(t.Context(), consumerScope)
	if err != nil {
		t.Fatal(err)
	}
	authority := tx.AuthorityRevision
	tx.Tx.Rollback(t.Context())
	headers := map[string]string{"Authorization": "Bearer " + string(consumerToken.Bytes)}
	selection := workflow.CollectionSelection{Workflow: workflow.Reference{ID: declared.ID, Version: declared.Version, Hash: declared.Hash}, Timeout: 120, Authority: authority}
	before := count(consumer, consumerScope)
	_, raw := exchangeAPIRequest(t, consumerHTTP, "POST", consumerPrefix+"/workflow-collections/preview", nil, headers, exchangeAPIJSON(t, selection), 200)
	var preview workflow.CollectionPreview
	if json.Unmarshal(raw, &preview) != nil || preview.ExternalContact || !preview.ApprovalRequired || preview.Definition.Connection.DAV == nil || count(consumer, consumerScope) != before || count(producer, producerScope) != producerBefore {
		t.Fatal("DAV metadata preview contacted a source,created effects or lost read-only role")
	}
	_, listRaw := exchangeAPIRequest(t, consumerHTTP, "GET", consumerPrefix+"/workflow-collection-connections", nil, headers, nil, 200)
	for _, value := range []string{string(sourceCredential.Bytes), caRef, tokenRef, secure.Digest(sourceCredential.Bytes), "token_sha256"} {
		if bytes.Contains(listRaw, []byte(value)) || bytes.Contains(raw, []byte(value)) {
			t.Fatal("DAV public review leaked protected credential value,proof or reference")
		}
	}
	headers["Idempotency-Key"] = "dav-collection-admit"
	_, raw = exchangeAPIRequest(t, consumerHTTP, "POST", consumerPrefix+"/workflow-collections", nil, headers, exchangeAPIJSON(t, workflow.CollectionStartRequest{Selection: selection, Hash: preview.Hash}), 200)
	var admitted workflow.Result
	var action workflow.CollectionAction
	if json.Unmarshal(raw, &admitted) != nil || json.Unmarshal(admitted.Resource, &action) != nil || action.Kind != "workflow_collection" || !store.ValidID(action.ID) {
		t.Fatal("DAV admission receipt invalid")
	}
	initial, err := engine.CollectionStatus(t.Context(), consumerScope, action.ID)
	if err != nil || initial.Job == nil || initial.Job.Hash != action.Hash {
		t.Fatal("DAV admitted job status differs", err)
	}
	job := initial.Job
	headers["Idempotency-Key"] = "dav-collection-work"
	_, workedRaw := exchangeAPIRequest(t, consumerHTTP, "POST", consumerPrefix+"/workflow-collections/"+job.ID+"/work", nil, headers, exchangeAPIJSON(t, workflow.CollectionWorkRequest{Hash: job.Hash}), 200)
	view, err := engine.CollectionStatus(t.Context(), consumerScope, job.ID)
	if err != nil || !view.Current || !view.Job.Captured || view.Job.State != "captured" || view.Job.Attempts != 1 || view.Job.Fence != 1 || len(view.Inputs) != 1 || view.BusinessAcceptance != "unknown" {
		t.Fatal("actual served DAV capture did not commit the exact custody outcome", err)
	}
	input := view.Inputs[0]
	stored, stream, err := consumer.DownloadPath(t.Context(), consumerScope, input.Target)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(io.LimitReader(stream, int64(len(data))+1))
	stream.Close()
	if err != nil || !bytes.Equal(actual, data) || stored.ID != input.ObjectID || stored.ID == file.ID || stored.SHA256 != file.SHA256 || stored.Size != file.Size || input.FileID == nil || *input.FileID != stored.ID {
		t.Fatal("independent destination custody read differs from the original DAV artifact")
	}
	after := count(consumer, consumerScope)
	if after[0] != before[0]+1 || after[1] != before[1] || after[2] != before[2] {
		t.Fatal("DAV collection gained unrelated custody or onward work")
	}
	readState, readEvents := snapshotProducer()
	expectedReads := map[davSourceReadBinding]int{
		{Actor: sourceParticipant.Actor, File: file.ID, SHA256: file.SHA256}:   1,
		{Actor: sourceParticipant.Actor, File: ready.ID, SHA256: ready.SHA256}: 1,
	}
	if readState != producerState || !davSourceReadAuditsMatch(producerEvents, readEvents, expectedReads) {
		t.Fatal("read-only DAV changed producer state or lost exact actor/file/hash read audit")
	}
	for path, want := range map[string]*store.File{"/inbox/input.dat": file, "/inbox/batch.ready.json": ready} {
		got, stream, err := producer.DownloadPath(t.Context(), producerScope, path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(stream, want.Size+1))
		stream.Close()
		if err != nil || *got != *want || secure.Digest(body) != want.SHA256 {
			t.Fatal("collection changed a producer revision or its exact bytes")
		}
	}
	verifiedState, verifiedEvents := snapshotProducer()
	expectedReads[davSourceReadBinding{Actor: producerActor, File: file.ID, SHA256: file.SHA256}] = 1
	expectedReads[davSourceReadBinding{Actor: producerActor, File: ready.ID, SHA256: ready.SHA256}] = 1
	if verifiedState != producerState || !davSourceReadAuditsMatch(producerEvents, verifiedEvents, expectedReads) {
		t.Fatal("independent producer verification changed state or exact read audit")
	}
	if err = os.Remove(tokenRef); err != nil {
		t.Fatal(err)
	}
	_, replayRaw := exchangeAPIRequest(t, consumerHTTP, "POST", consumerPrefix+"/workflow-collections/"+job.ID+"/work", nil, headers, exchangeAPIJSON(t, workflow.CollectionWorkRequest{Hash: job.Hash}), 200)
	var first, replay workflow.Result
	finalState, finalEvents := snapshotProducer()
	if json.Unmarshal(workedRaw, &first) != nil || json.Unmarshal(replayRaw, &replay) != nil || !replay.Replayed || !bytes.Equal(first.Resource, replay.Resource) || count(consumer, consumerScope) != after || finalState != producerState || !davSourceReadAuditsMatch(verifiedEvents, finalEvents, nil) {
		t.Fatal("saved original DAV work receipt reopened a missing credential or repeated effects")
	}
	t.Logf("served DAV source proof candidate=%s;arch=%s;content-sha256=%s;source-unchanged=true;captured-inputs=1;onward-effects=0;business-acceptance=unknown;independent-upstream-server-qualification=owed", commit, runtime.GOARCH, secure.Digest(data))
}
