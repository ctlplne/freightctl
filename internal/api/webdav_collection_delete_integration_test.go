//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVCollectionDeleteIsWholeAtomicAndRetainsImmutableCustody(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	apply := func(key string, command store.PathCommand) *store.PathResult {
		t.Helper()
		r, err := service.PathCommand(t.Context(), scope, key, command)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	stat := func(path string) store.PathEntry {
		t.Helper()
		e, err := service.StatPath(t.Context(), scope, path)
		if err != nil {
			t.Fatal(err)
		}
		return *e
	}
	writable := uint32(0770)
	root := apply("remove-root", store.PathCommand{Operation: "mkdir", Path: "/remove-tree", Mode: &writable})
	apply("remove-nested", store.PathCommand{Operation: "mkdir", Path: "/remove-tree/nested", Mode: &writable})
	data := []byte("deleting names never erases immutable custody\n")
	create := func(key, path string, payload []byte) *store.File {
		t.Helper()
		f, _, err := service.AcceptAt(t.Context(), scope, key, int64(len(payload)), secure.Digest(payload), bytes.NewReader(payload), custody.UploadTarget{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a := create("remove-a", "/remove-tree/a.dat", data)
	b := create("remove-b", "/remove-tree/nested/b.dat", data)
	property := namespaceprops.Change{Operation: "set", Property: `<x:label xmlns:x="urn:example" xml:lang="fr">inert <x:execute>never executed</x:execute></x:label>`}
	root = apply("remove-root-property", store.PathCommand{Operation: "properties", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision, PropertyChanges: []namespaceprops.Change{property}})
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	noRead, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "manage_paths"})
	noList, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "manage_paths"})
	noManage, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	headers := func(token *secure.Secret, key string, e store.PathEntry) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "X-Freightctl-Namespace-Revision": e.ID + ":" + strconv.FormatInt(e.Revision, 10), "Depth": "infinity"}
	}
	paths := []string{"/remove-tree", "/remove-tree/nested", "/remove-tree/a.dat", "/remove-tree/nested/b.dat"}
	snapshot := func() map[string]store.PathEntry {
		t.Helper()
		entries := map[string]store.PathEntry{}
		for _, path := range paths {
			e := stat(path)
			e.Modified = e.Modified.UTC()
			entries[path] = e
		}
		return entries
	}
	unchanged := func(before map[string]store.PathEntry) {
		t.Helper()
		if !maps.Equal(before, snapshot()) {
			t.Fatal("refused recursive removal changed a member or revision")
		}
	}
	source := prefix + "/dav/remove-tree/"
	before := snapshot()
	for _, token := range []*secure.Secret{noRead, noList, noManage} {
		exchangeAPIRequest(t, server, "DELETE", source, nil, headers(token, "remove-denied", root.Entry), nil, 403)
		unchanged(before)
	}
	entryB := stat(paths[3])
	private := uint32(0600)
	protected := apply("remove-private", store.PathCommand{Operation: "setstat", Path: entryB.Path, ExpectedRevision: &entryB.Revision, Mode: &private})
	apply("remove-alias", store.PathCommand{Operation: "publish", Path: "/outside-alias.dat", FileID: b.ID})
	_, alias := exchangeAPIRequest(t, server, "GET", prefix+"/dav/outside-alias.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if !bytes.Equal(alias, data) {
		t.Fatal("readable alias fixture differs")
	}
	before = snapshot()
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers(operator, "remove-private-refused", root.Entry), nil, 403)
	unchanged(before)
	readable := uint32(0640)
	apply("remove-private-restored", store.PathCommand{Operation: "setstat", Path: entryB.Path, ExpectedRevision: &protected.Entry.Revision, Mode: &readable})
	nested := stat(paths[1])
	readOnly := uint32(0750)
	protectedDir := apply("remove-readonly-dir", store.PathCommand{Operation: "setstat", Path: nested.Path, ExpectedRevision: &nested.Revision, Mode: &readOnly})
	before = snapshot()
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers(operator, "remove-directory-refused", root.Entry), nil, 403)
	unchanged(before)
	apply("remove-directory-restored", store.PathCommand{Operation: "setstat", Path: nested.Path, ExpectedRevision: &protectedDir.Entry.Revision, Mode: &writable})
	before = snapshot()
	stale := root.Entry
	stale.Revision++
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers(operator, "remove-stale", stale), nil, 412)
	unchanged(before)
	command := headers(operator, "remove-original", root.Entry)
	response, raw := exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 204)
	if len(raw) != 0 || response.Header.Get("X-Freightctl-Namespace-State") != "collection-removed-at-commit" || response.Header.Get("X-Freightctl-Removed-Entries") != "4" || !store.ValidID(response.Header.Get("X-Freightctl-Event-ID")) || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("collection removal invented bytes/current location or lost its complete result")
	}
	for _, path := range paths {
		for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
			exchangeAPIRequest(t, server, method, prefix+"/dav"+path, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Depth": "0"}, nil, 404)
		}
	}
	for _, f := range []*store.File{a, b} {
		_, actual := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+f.ID, nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
		if !bytes.Equal(actual, data) {
			t.Fatal("recursive removal erased retained custody")
		}
	}
	// The outside mapping survives,and removal confers no new authority to
	// custody that has no surviving readable mapping for this participant.
	exchangeAPIRequest(t, server, "GET", prefix+"/files/"+a.ID, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 404)
	_, alias = exchangeAPIRequest(t, server, "GET", prefix+"/dav/outside-alias.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if !bytes.Equal(alias, data) {
		t.Fatal("collection removal crossed its source boundary")
	}
	exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 412)
	// Recover the old transaction's private evidence without requiring a
	// surviving path or dispatching the destructive command again.
	originalCommand := store.PathCommand{Operation: "remove_tree", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision}
	receiptHeaders := map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "remove-original"}
	response, raw = exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, receiptHeaders, exchangeAPIJSON(t, originalCommand), 200)
	var originalReceipt store.PathCommandReceipt
	if json.Unmarshal(raw, &originalReceipt) != nil || originalReceipt.Profile != "namespace-command-receipt-v1" || originalReceipt.Observation != "original-commit-not-current-state" || originalReceipt.RequestKey != "remove-original" || len(originalReceipt.RequestHash) != 64 || !store.ValidID(originalReceipt.CompletedEventID) || originalReceipt.Result.Replayed || originalReceipt.Result.Changed != 4 || !originalReceipt.Result.Entry.Deleted || originalReceipt.Result.Entry.ID != root.Entry.ID || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" {
		t.Fatal("lost DELETE response could not recover exact private historical evidence without current-state assertion")
	}
	otherReceiptHeaders := map[string]string{"Authorization": "Bearer " + string(other.Bytes), "Idempotency-Key": "remove-original"}
	_, otherBody := exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, otherReceiptHeaders, exchangeAPIJSON(t, originalCommand), 404)
	unknownHeaders := map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "remove-unknown"}
	_, unknownBody := exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, unknownHeaders, exchangeAPIJSON(t, originalCommand), 404)
	changedCommand := originalCommand
	changedCommand.Path = "/another"
	_, changedBody := exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, receiptHeaders, exchangeAPIJSON(t, changedCommand), 404)
	if !bytes.Equal(otherBody, unknownBody) || !bytes.Equal(changedBody, unknownBody) {
		t.Fatal("receipt selection disclosed another actor or a changed command meaning")
	}
	for _, token := range []*secure.Secret{noRead, noList, noManage} {
		exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": "remove-original"}, exchangeAPIJSON(t, originalCommand), 403)
	}
	browserCommand := store.PathCommand{Operation: "mkdir", Path: root.Entry.Path, Mode: &writable}
	browserHeaders := map[string]string{"Origin": server.URL, "X-CSRF-Token": csrf, "Idempotency-Key": "remove-root"}
	_, browserRaw := exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", cookie, browserHeaders, exchangeAPIJSON(t, browserCommand), 200)
	var browserReceipt store.PathCommandReceipt
	if json.Unmarshal(browserRaw, &browserReceipt) != nil || browserReceipt.Observation != "original-commit-not-current-state" || browserReceipt.Result.Entry.ID != root.Entry.ID || browserReceipt.Result.Entry.Deleted || browserReceipt.Result.Entry.Revision != 1 {
		t.Fatal("browser receipt changed old creation evidence after current removal")
	}
	exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", cookie, map[string]string{"Origin": server.URL, "Idempotency-Key": "remove-root"}, exchangeAPIJSON(t, browserCommand), 403)
	// Recreate the root at the same path and invoke the old key. Even a
	// matching revision on another identity cannot recover the private receipt.
	replacement := apply("remove-recreate", store.PathCommand{Operation: "mkdir", Path: root.Entry.Path, Mode: &writable})
	exchangeAPIRequest(t, server, "DELETE", source, nil, command, nil, 412)
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers(operator, "remove-original", replacement.Entry), nil, 409)
	if actual := stat(root.Entry.Path); actual.ID != replacement.Entry.ID || actual.Revision != replacement.Entry.Revision {
		t.Fatal("old command removed replacement collection")
	}
	aba := apply("remove-aba-root", store.PathCommand{Operation: "mkdir", Path: "/aba-remove", Mode: &writable})
	apply("remove-aba-delete", store.PathCommand{Operation: "rmdir", Path: aba.Entry.Path, ExpectedRevision: &aba.Entry.Revision})
	newABA := apply("remove-aba-recreate", store.PathCommand{Operation: "mkdir", Path: aba.Entry.Path, Mode: &writable})
	if aba.Entry.ID == newABA.Entry.ID || aba.Entry.Revision != newABA.Entry.Revision {
		t.Fatal("ABA fixture is not equal-revision/different-identity")
	}
	exchangeAPIRequest(t, server, "DELETE", prefix+"/dav/aba-remove/", nil, headers(operator, "remove-aba-refused", aba.Entry), nil, 412)
	// Deleted rows are irreversible tombstones under the existing SQL guard.
	// Inspect their exact metadata rather than inventing an undelete operation
	// solely to make historical command replay appear reachable.
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range before {
		var tombstone store.PathEntry
		var propertyJSON []byte
		if err = tx.Tx.QueryRow(t.Context(), `SELECT entry_id::text,path,parent_path,kind,COALESCE(file_id::text,''),owner_actor_id::text,mode,modified_at,revision,deleted,changed_event_id::text,namespace_properties FROM namespace_entries WHERE entry_id=$1`, old.ID).Scan(&tombstone.ID, &tombstone.Path, &tombstone.Parent, &tombstone.Kind, &tombstone.FileID, &tombstone.Owner, &tombstone.Mode, &tombstone.Modified, &tombstone.Revision, &tombstone.Deleted, &tombstone.EventID, &propertyJSON); err != nil {
			t.Fatal(err)
		}
		if !tombstone.Deleted || tombstone.Revision != old.Revision+1 || tombstone.Path != old.Path || tombstone.Parent != old.Parent || tombstone.Kind != old.Kind || tombstone.FileID != old.FileID || tombstone.Owner != old.Owner || tombstone.Mode != old.Mode || !tombstone.Modified.Equal(old.Modified) || !store.ValidID(tombstone.EventID) {
			t.Fatal("removed member lost its exact custody/identity/metadata tombstone")
		}
		var props map[string]string
		if json.Unmarshal(propertyJSON, &props) != nil || (old.ID == root.Entry.ID && props["{urn:example}label"] != property.Property) {
			t.Fatal("removed root lost its inert property tombstone")
		}
	}
	if err = tx.Tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "DELETE", source, nil, headers(other, "remove-original", root.Entry), nil, 412)
	// Current policy unavailability on one child refuses the entire tree.
	controlledRoot := apply("remove-controlled-root", store.PathCommand{Operation: "mkdir", Path: "/remove-controlled", Mode: &writable})
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "remove-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("remove-controlled", "/remove-controlled/input.csv", []byte("record\nreleased then revoked\n"))
	if _, err = checking.Run(t.Context(), scope, controlled.ID, "remove-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled fixture not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "remove-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "remove-policy-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "DELETE", prefix+"/dav/remove-controlled/", nil, headers(operator, "remove-policy-refused", controlledRoot.Entry), nil, 409)
	if e := stat(controlledRoot.Entry.Path); e.ID != controlledRoot.Entry.ID || e.Revision != controlledRoot.Entry.Revision {
		t.Fatal("unavailable child partially removed its parent")
	}
	if _, err = service.StatPath(t.Context(), scope, "/remove-controlled/input.csv"); err != nil {
		t.Fatal("unavailable child mapping was partially removed", err)
	}
	tx, err = service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var removed, commands, intents, runs, accepts int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathRemoved'),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted')`, participant.Actor).Scan(&removed, &commands, &intents, &runs, &accepts); err != nil || removed != 4 || commands != 1 || intents != 0 || runs != 0 || accepts != 0 {
		t.Fatal("recursive removal lost atomic member events/private receipt or caused external effects", removed, commands, intents, runs, accepts, err)
	}
	if _, err = tx.Entry(t.Context(), "/remove-tree/nested/b.dat"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("deleted descendant is active", err)
	}
}
