//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/freightctl/internal/checks"
	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVCollectionMoveIsCompleteAtomicAuthorizedAndPreservesCustody(t *testing.T) {
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
	sameEntry := func(a, b store.PathEntry) bool {
		a.Modified = a.Modified.UTC()
		b.Modified = b.Modified.UTC()
		return a == b
	}
	root := apply("tree-source", store.PathCommand{Operation: "mkdir", Path: "/source"})
	apply("tree-nested", store.PathCommand{Operation: "mkdir", Path: "/source/nested"})
	apply("tree-occupied", store.PathCommand{Operation: "mkdir", Path: "/occupied"})
	payload := []byte("all members retain their exact immutable custody\n")
	create := func(key, path string, data []byte) *store.File {
		t.Helper()
		f, _, err := service.AcceptAt(t.Context(), scope, key, int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a := create("tree-a", "/source/a.dat", payload)
	b := create("tree-b", "/source/nested/b.dat", payload)
	label := namespaceprops.Change{Operation: "set", Property: `<x:label xmlns:x="urn:example" xml:lang="fr">retained <x:execute approved="true">data only</x:execute></x:label>`}
	root = apply("tree-root-property", store.PathCommand{Operation: "properties", Path: root.Entry.Path, ExpectedEntryID: root.Entry.ID, ExpectedRevision: &root.Entry.Revision, PropertyChanges: []namespaceprops.Change{label}})
	entryA, err := service.StatPath(t.Context(), scope, "/source/a.dat")
	if err != nil {
		t.Fatal(err)
	}
	apply("tree-child-property", store.PathCommand{Operation: "properties", Path: entryA.Path, ExpectedEntryID: entryA.ID, ExpectedRevision: &entryA.Revision, PropertyChanges: []namespaceprops.Change{label}})
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	missingRead, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "manage_paths"})
	missingList, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "manage_paths"})
	missingManagement, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	headers := func(token *secure.Secret, key, destination string, entry store.PathEntry) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "X-Freightctl-Namespace-Revision": entry.ID + ":" + strconv.FormatInt(entry.Revision, 10), "Overwrite": "F", "Depth": "infinity", "Destination": server.URL + prefix + "/dav" + destination + "/"}
	}
	source := prefix + "/dav/source/"
	for _, token := range []*secure.Secret{missingRead, missingList, missingManagement} {
		exchangeAPIRequest(t, server, "MOVE", source, nil, headers(token, "tree-denied", "/moved", root.Entry), nil, 403)
	}
	entryB, err := service.StatPath(t.Context(), scope, "/source/nested/b.dat")
	if err != nil {
		t.Fatal(err)
	}
	private := uint32(0600)
	protected := apply("tree-private-child", store.PathCommand{Operation: "setstat", Path: entryB.Path, ExpectedRevision: &entryB.Revision, Mode: &private})
	apply("tree-readable-alias", store.PathCommand{Operation: "publish", Path: "/readable-alias.dat", FileID: b.ID})
	_, aliasBytes := exchangeAPIRequest(t, server, "GET", prefix+"/dav/readable-alias.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if !bytes.Equal(aliasBytes, payload) {
		t.Fatal("private member's independent readable alias fixture differs")
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(operator, "tree-private-refused", "/moved", root.Entry), nil, 403)
	unchanged, err := service.StatPath(t.Context(), scope, root.Entry.Path)
	if err != nil || !sameEntry(*unchanged, root.Entry) {
		t.Fatal("private child refusal moved part of the source", err)
	}
	readable := uint32(0640)
	apply("tree-restored-child", store.PathCommand{Operation: "setstat", Path: entryB.Path, ExpectedRevision: &protected.Entry.Revision, Mode: &readable})
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(operator, "tree-occupied-refused", "/occupied", root.Entry), nil, 412)
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(operator, "tree-missing-parent", "/missing/moved", root.Entry), nil, 409)
	before := map[string]store.PathEntry{}
	properties := map[string]map[string]string{}
	for _, path := range []string{"/source", "/source/nested", "/source/a.dat", "/source/nested/b.dat"} {
		e, err := service.StatPath(t.Context(), scope, path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = *e
		p, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, path)
		if err != nil {
			t.Fatal(err)
		}
		properties[path] = p.Properties
	}
	command := headers(operator, "tree-original", "/moved", root.Entry)
	response, raw := exchangeAPIRequest(t, server, "MOVE", source, nil, command, nil, 201)
	var result struct {
		Result store.PathResult `json:"result"`
		State  string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Result.Changed != 4 || result.Result.Replayed || result.Result.Entry.ID != root.Entry.ID || result.Result.Entry.Revision != root.Entry.Revision+1 || result.State != "collection-moved-at-commit" || response.Header.Get("Location") != prefix+"/dav/moved/" || response.Header.Get("ETag") != "" {
		t.Fatal("full collection move lost its atomic result or honest location")
	}
	for path, old := range before {
		moved := "/moved" + path[len("/source"):]
		next, err := service.StatPath(t.Context(), scope, moved)
		if err != nil {
			t.Fatal(err)
		}
		if next.ID != old.ID || next.FileID != old.FileID || next.Owner != old.Owner || next.Mode != old.Mode || next.Kind != old.Kind || !next.Modified.Equal(old.Modified) || next.Revision != old.Revision+1 {
			t.Fatal("collection movement changed member identity,custody,mode,time or revision")
		}
		p, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, moved)
		if err != nil || !maps.Equal(p.Properties, properties[path]) {
			t.Fatal("collection move lost inert XML properties", err)
		}
		exchangeAPIRequest(t, server, "PROPFIND", prefix+"/dav"+path, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Depth": "0"}, nil, 404)
		if old.Kind == "file" {
			response, actual := exchangeAPIRequest(t, server, "GET", prefix+"/dav"+moved, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
			if !bytes.Equal(actual, payload) || response.Header.Get("X-File-Revision-ID") != old.FileID {
				t.Fatal("independent moved member read differs from original immutable bytes")
			}
		}
	}
	for _, file := range []*store.File{a, b} {
		_, actual := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+file.ID, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
		if !bytes.Equal(actual, payload) {
			t.Fatal("collection move destroyed retained custody")
		}
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, command, nil, 412)
	restored := apply("tree-admin-restore", store.PathCommand{Operation: "rename", Path: "/moved", Target: "/source", ExpectedRevision: &result.Result.Entry.Revision})
	_, raw = exchangeAPIRequest(t, server, "MOVE", source, nil, command, nil, 200)
	if json.Unmarshal(raw, &result) != nil || !result.Result.Replayed || result.State != "not-asserted-original-receipt" {
		t.Fatal("historical collection receipt repeated the tree move")
	}
	actual, err := service.StatPath(t.Context(), scope, "/source")
	if err != nil || actual.ID != restored.Entry.ID || actual.Revision != restored.Entry.Revision {
		t.Fatal("historical receipt changed restored tree", err)
	}
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(operator, "tree-stale", "/moved", root.Entry), nil, 412)
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(other, "tree-original", "/moved", root.Entry), nil, 412)
	exchangeAPIRequest(t, server, "MOVE", source, nil, headers(operator, "tree-original", "/different", root.Entry), nil, 409)
	// The original actor's exact root revision cannot match another directory
	// recreated at the same path and revision;no history is reusable across IDs.
	abadir := apply("tree-aba-dir", store.PathCommand{Operation: "mkdir", Path: "/aba"})
	apply("tree-aba-remove", store.PathCommand{Operation: "rmdir", Path: "/aba", ExpectedRevision: &abadir.Entry.Revision})
	newdir := apply("tree-aba-recreate", store.PathCommand{Operation: "mkdir", Path: "/aba"})
	if newdir.Entry.ID == abadir.Entry.ID || newdir.Entry.Revision != abadir.Entry.Revision {
		t.Fatal("directory ABA fixture is not exact")
	}
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/aba/", nil, headers(operator, "tree-aba-refused", "/aba-moved", abadir.Entry), nil, 412)
	// A mapped file whose release policy is no longer current blocks the whole
	// tree. An unverified held upload never enters the namespace in the first place.
	controlledRoot := apply("tree-controlled-root", store.PathCommand{Operation: "mkdir", Path: "/controlled"})
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "tree-csv-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlled := create("tree-controlled", "/controlled/input.csv", []byte("record\nreleased then revoked\n"))
	if _, err = checking.Run(t.Context(), scope, controlled.ID, "tree-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled tree fixture not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "tree-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "tree-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/controlled/", nil, headers(operator, "tree-policy-refused", "/controlled-moved", controlledRoot.Entry), nil, 409)
	actual, err = service.StatPath(t.Context(), scope, "/controlled")
	if err != nil || !sameEntry(*actual, controlledRoot.Entry) {
		t.Fatal("unavailable child partially moved its tree", err)
	}
	large := apply("tree-large-root", store.PathCommand{Operation: "mkdir", Path: "/large"})
	// Populate an oversized retained-state fixture through the exact low-level
	// journal guard. Keep the application's1000-entry quota unchanged;this tests
	// fail-closed processing of old data or a subsequently lowered configuration,
	// not permission for ordinary creation to bypass its live-entry quota.
	tx, err := service.DB.Begin(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.NamespaceLock(t.Context()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		entry := store.PathEntry{ID: secure.NewID(), Path: fmt.Sprintf("/large/d%04d", i), Kind: "dir", Owner: tx.Actor, Mode: 0750, Modified: time.Now().UTC(), Revision: 1}
		if err = tx.SaveEntry(t.Context(), nil, &entry, "PathCreated", "tree-capacity-fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "MOVE", prefix+"/dav/large/", nil, headers(operator, "tree-capacity-refused", "/large-moved", large.Entry), nil, 507)
	if _, err = service.StatPath(t.Context(), scope, "/large/d0000"); err != nil {
		t.Fatal("bounded refusal moved a prefix", err)
	}
	if _, err = service.StatPath(t.Context(), scope, "/large-moved"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("bounded refusal created a partial target", err)
	}
	deleteHeaders := headers(operator, "tree-delete-capacity-refused", "/unused", large.Entry)
	delete(deleteHeaders, "Destination")
	delete(deleteHeaders, "Overwrite")
	exchangeAPIRequest(t, server, "DELETE", prefix+"/dav/large/", nil, deleteHeaders, nil, 507)
	if first, err := service.StatPath(t.Context(), scope, "/large/d0000"); err != nil || first.Revision != 1 {
		t.Fatal("bounded removal deleted or revised a prefix", err)
	}
	if current, err := service.StatPath(t.Context(), scope, "/large"); err != nil || !sameEntry(*current, large.Entry) {
		t.Fatal("bounded removal changed its root", err)
	}
	copyOperator, copyParticipant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	exchangeAPIRequest(t, server, "COPY", prefix+"/dav/large/", nil, headers(copyOperator, "tree-copy-capacity-refused", "/large-copy", large.Entry), nil, 507)
	if _, err = service.StatPath(t.Context(), scope, "/large-copy"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("oversized copy published a prefix", err)
	}
	copyScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(copyOperator.Bytes)}
	copyTx, err := service.DB.Begin(t.Context(), copyScope)
	if err != nil {
		t.Fatal(err)
	}
	var copied, copyCommands int
	if err = copyTx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind IN ('PathCreated','PathPublished','PathAttrsChanged')),(SELECT count(*) FROM namespace_commands)`, copyParticipant.Actor).Scan(&copied, &copyCommands); err != nil || copied != 0 || copyCommands != 0 {
		t.Fatal("oversized copy retained events or private receipts", copied, copyCommands, err)
	}
	if err = copyTx.Tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Each tree fits the old limit separately;their combined overwrite must
	// still fit the same1000-entry operation bound. Reuse the retained fixture,
	// reduce it by one entry and never raise the namespace quota.
	one := int64(1)
	apply("tree-budget-remove-one", store.PathCommand{Operation: "rmdir", Path: "/large/d0999", ExpectedRevision: &one})
	budgetSource, err := service.StatPath(t.Context(), scope, "/occupied")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"MOVE", "COPY"} {
		h := headers(admin, "tree-combined-"+strings.ToLower(method), "/large", *budgetSource)
		h["Overwrite"] = "T"
		h["X-Freightctl-Destination-Revision"] = large.Entry.ID + ":" + strconv.FormatInt(large.Entry.Revision, 10)
		exchangeAPIRequest(t, server, method, prefix+"/dav/occupied/", nil, h, nil, 507)
		if current, err := service.StatPath(t.Context(), scope, "/occupied"); err != nil || !sameEntry(*current, *budgetSource) {
			t.Fatal("combined overwrite limit changed source", err)
		}
		if current, err := service.StatPath(t.Context(), scope, "/large"); err != nil || !sameEntry(*current, large.Entry) {
			t.Fatal("combined overwrite limit changed target root", err)
		}
		if child, err := service.StatPath(t.Context(), scope, "/large/d0000"); err != nil || child.Revision != 1 {
			t.Fatal("combined overwrite limit removed a prefix", err)
		}
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err = service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var moved, commands, intents, runs, accepts, removed int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathMoved'),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathRemoved')`, participant.Actor).Scan(&moved, &commands, &intents, &runs, &accepts, &removed); err != nil || moved != 4 || commands != 1 || intents != 0 || runs != 0 || accepts != 0 || removed != 0 {
		t.Fatal("collection move lost complete atomic effects or actor-private single receipt", moved, commands, intents, runs, accepts, removed, err)
	}
}
