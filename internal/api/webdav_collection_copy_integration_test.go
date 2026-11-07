//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestWebDAVCollectionCopySeparatesMappingsAndPreservesExactPropertiesAndCustody(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	apply := func(key string, c store.PathCommand) *store.PathResult {
		t.Helper()
		r, err := service.PathCommand(t.Context(), scope, key, c)
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
	root := apply("copy-tree-root", store.PathCommand{Operation: "mkdir", Path: "/copy-tree"})
	nested := apply("copy-tree-nested", store.PathCommand{Operation: "mkdir", Path: "/copy-tree/nested"})
	data := []byte("independent collection names retain the same exact immutable bytes\n")
	files := map[string]*store.File{}
	for i, path := range []string{"/copy-tree/a.dat", "/copy-tree/nested/b.dat"} {
		f, _, err := service.AcceptAt(t.Context(), scope, "copy-tree-file-"+strconv.Itoa(i), int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: path})
		if err != nil {
			t.Fatal(err)
		}
		files[path] = f
	}
	property := namespaceprops.Change{Operation: "set", Property: `<x:label xmlns:x="urn:example" xml:lang="fr">inert <x:execute>data only</x:execute></x:label>`}
	for _, path := range []string{root.Entry.Path, nested.Entry.Path, "/copy-tree/a.dat"} {
		e := stat(path)
		apply("copy-tree-property-"+strings.ReplaceAll(path, "/", "-"), store.PathCommand{Operation: "properties", Path: path, ExpectedEntryID: e.ID, ExpectedRevision: &e.Revision, PropertyChanges: []namespaceprops.Change{property}})
	}
	root.Entry = stat(root.Entry.Path)
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	noRead, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"list", "write", "manage_paths"})
	noList, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "write", "manage_paths"})
	noWrite, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	headers := func(token *secure.Secret, key, target, depth string, e store.PathEntry) map[string]string {
		h := map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "X-Freightctl-Namespace-Revision": e.ID + ":" + strconv.FormatInt(e.Revision, 10), "Overwrite": "F", "Destination": server.URL + prefix + "/dav" + target + "/"}
		if depth != "" {
			h["Depth"] = depth
		}
		return h
	}
	source := prefix + "/dav/copy-tree/"
	for _, token := range []*secure.Secret{noRead, noList, noWrite} {
		exchangeAPIRequest(t, server, "COPY", source, nil, headers(token, "copy-tree-denied", "/tree-copy", "infinity", root.Entry), nil, 403)
	}
	private := uint32(0600)
	readable := uint32(0640)
	b := stat("/copy-tree/nested/b.dat")
	protected := apply("copy-tree-private", store.PathCommand{Operation: "setstat", Path: b.Path, ExpectedRevision: &b.Revision, Mode: &private})
	apply("copy-tree-alias", store.PathCommand{Operation: "publish", Path: "/copy-readable-alias.dat", FileID: b.FileID})
	_, alias := exchangeAPIRequest(t, server, "GET", prefix+"/dav/copy-readable-alias.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if !bytes.Equal(alias, data) {
		t.Fatal("private child alias fixture differs")
	}
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-private-refused", "/tree-copy", "infinity", root.Entry), nil, 403)
	// Depth0 copies the collection's own properties and never consults or
	// copies children,including a child this participant cannot read.
	response, raw := exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-shallow", "/tree-shallow", "0", root.Entry), nil, 201)
	var result struct {
		Result store.PathResult `json:"result"`
		State  string           `json:"namespace_state"`
		Depth  string           `json:"depth"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Result.Changed != 1 || result.Result.Entry.ID == root.Entry.ID || result.Result.Entry.Owner != participant.Actor || result.Result.Entry.Mode != 0750 || result.Result.Entry.Revision != 2 || result.Depth != "0" || result.State != "collection-copied-at-commit" || response.Header.Get("Location") != prefix+"/dav/tree-shallow/" || response.Header.Get("ETag") != "" {
		t.Fatal("shallow copy lost independent collection/property initialization")
	}
	shallow, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, "/tree-shallow")
	if err != nil || shallow.Properties["{urn:example}label"] != property.Property {
		t.Fatal("shallow collection lost exact inert properties", err)
	}
	if _, err = service.StatPath(t.Context(), scope, "/tree-shallow/nested"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("Depth0 copied a child", err)
	}
	apply("copy-tree-private-restored", store.PathCommand{Operation: "setstat", Path: b.Path, ExpectedRevision: &protected.Entry.Revision, Mode: &readable})
	before := map[string]store.PathEntry{}
	props := map[string]map[string]string{}
	for _, path := range []string{"/copy-tree", "/copy-tree/nested", "/copy-tree/a.dat", "/copy-tree/nested/b.dat"} {
		e := stat(path)
		e.Modified = e.Modified.UTC()
		before[path] = e
		p, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, path)
		if err != nil {
			t.Fatal(err)
		}
		props[path] = p.Properties
	}
	unchanged := func() {
		t.Helper()
		for path, e := range before {
			actual := stat(path)
			actual.Modified = actual.Modified.UTC()
			if actual != e {
				t.Fatal("collection copy changed source metadata or revision")
			}
		}
	}
	stale := root.Entry
	stale.Revision++
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-stale", "/tree-copy", "infinity", stale), nil, 412)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-self", "/copy-tree", "infinity", root.Entry), nil, 403)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-descendant", "/copy-tree/copy", "0", root.Entry), nil, 403)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-missing-parent", "/missing/tree-copy", "infinity", root.Entry), nil, 409)
	// Lower only the test configuration to prove that insufficient aggregate
	// live-entry capacity refuses all mappings;never raise the product quota.
	limit := service.NamespaceMaxEntries
	t.Cleanup(func() { service.NamespaceMaxEntries = limit })
	service.NamespaceMaxEntries = 1
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-no-capacity", "/tree-copy", "infinity", root.Entry), nil, 507)
	service.NamespaceMaxEntries = limit
	if _, err = service.StatPath(t.Context(), scope, "/tree-copy"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("capacity refusal published a prefix", err)
	}
	unchanged()
	command := headers(operator, "copy-tree-original", "/tree-copy", "", root.Entry)
	response, raw = exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 201)
	if json.Unmarshal(raw, &result) != nil || result.Result.Replayed || result.Result.Changed != 4 || result.Depth != "infinity" || result.State != "collection-copied-at-commit" || result.Result.Entry.ID == root.Entry.ID || response.Header.Get("Location") != prefix+"/dav/tree-copy/" || response.Header.Get("ETag") != "" {
		t.Fatal("full collection copy lost complete fresh result")
	}
	unchanged()
	for path, old := range before {
		target := "/tree-copy" + strings.TrimPrefix(path, "/copy-tree")
		next := stat(target)
		wantMode := uint32(0640)
		wantRevision := int64(1)
		if old.Kind == "dir" {
			wantMode = 0750
			if len(props[path]) > 0 {
				wantRevision = 2
			}
		}
		if next.ID == old.ID || next.Kind != old.Kind || next.FileID != old.FileID || next.Owner != participant.Actor || next.Mode != wantMode || next.Revision != wantRevision {
			t.Fatal("copied mapping reused source identity/authority or changed custody")
		}
		p, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, target)
		if err != nil || !maps.Equal(p.Properties, props[path]) {
			t.Fatal("collection copy lost exact inert properties", err)
		}
		if old.Kind == "file" {
			response, body := exchangeAPIRequest(t, server, "GET", prefix+"/dav"+target, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
			if !bytes.Equal(body, data) || response.Header.Get("X-File-Revision-ID") != files[path].ID {
				t.Fatal("independent copied member bytes or immutable identity differs")
			}
		}
	}
	response, raw = exchangeAPIRequest(t, server, "COPY", source, nil, command, nil, 200)
	if json.Unmarshal(raw, &result) != nil || !result.Result.Replayed || result.State != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
		t.Fatal("copy retry invented a current destination or repeated publication")
	}
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(other, "copy-tree-original", "/tree-copy", "infinity", root.Entry), nil, 412)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-original", "/different", "infinity", root.Entry), nil, 409)
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-original", "/tree-copy", "0", root.Entry), nil, 409)
	// A copied property's later change is independent of its source snapshot.
	copiedA := stat("/tree-copy/a.dat")
	apply("copy-tree-independent-property", store.PathCommand{Operation: "properties", Path: copiedA.Path, ExpectedEntryID: copiedA.ID, ExpectedRevision: &copiedA.Revision, PropertyChanges: []namespaceprops.Change{{Operation: "set", Property: `<label xmlns="urn:example">new independent data</label>`}}})
	p, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, "/copy-tree/a.dat")
	if err != nil || !maps.Equal(p.Properties, props["/copy-tree/a.dat"]) {
		t.Fatal("copied metadata change modified source", err)
	}
	unchanged()
	// A matching path/revision on a new collection cannot reuse old identity.
	aba := apply("copy-tree-aba-root", store.PathCommand{Operation: "mkdir", Path: "/copy-aba"})
	apply("copy-tree-aba-remove", store.PathCommand{Operation: "rmdir", Path: aba.Entry.Path, ExpectedRevision: &aba.Entry.Revision})
	recreated := apply("copy-tree-aba-recreate", store.PathCommand{Operation: "mkdir", Path: aba.Entry.Path})
	if recreated.Entry.ID == aba.Entry.ID || recreated.Entry.Revision != aba.Entry.Revision {
		t.Fatal("copy ABA fixture is not equal-revision/different-identity")
	}
	exchangeAPIRequest(t, server, "COPY", prefix+"/dav/copy-aba/", nil, headers(operator, "copy-tree-aba-refused", "/copy-aba-target", "infinity", aba.Entry), nil, 412)
	if _, err = service.StatPath(t.Context(), scope, "/copy-aba-target"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("copy ABA refusal published a target", err)
	}
	// Readable contents do not grant destination-parent write.
	apply("copy-tree-readonly-parent", store.PathCommand{Operation: "mkdir", Path: "/copy-readonly"})
	exchangeAPIRequest(t, server, "COPY", source, nil, headers(operator, "copy-tree-parent-refused", "/copy-readonly/target", "infinity", root.Entry), nil, 403)
	if _, err = service.StatPath(t.Context(), scope, "/copy-readonly/target"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("parent write refusal published a destination", err)
	}
	unchanged()
	controlledRoot := apply("copy-tree-controlled-root", store.PathCommand{Operation: "mkdir", Path: "/copy-controlled"})
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "copy-tree-policy", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	controlledData := []byte("record\nreleased then revoked\n")
	controlled, _, err := service.AcceptAt(t.Context(), scope, "copy-tree-controlled-file", int64(len(controlledData)), secure.Digest(controlledData), bytes.NewReader(controlledData), custody.UploadTarget{Path: "/copy-controlled/input.csv"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Run(t.Context(), scope, controlled.ID, "copy-tree-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, controlled.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("controlled copy fixture not passed", err)
	}
	if _, err = checking.Release(t.Context(), scope, controlled.ID, "copy-tree-release", checks.ReleaseDecision{SHA256: controlled.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "copy-tree-policy-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	exchangeAPIRequest(t, server, "COPY", prefix+"/dav/copy-controlled/", nil, headers(operator, "copy-tree-policy-refused", "/copy-controlled-target", "infinity", controlledRoot.Entry), nil, 409)
	if _, err = service.StatPath(t.Context(), scope, "/copy-controlled-target"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unavailable child copy published a prefix", err)
	}
	if actual := stat(controlledRoot.Entry.Path); actual.ID != controlledRoot.Entry.ID || actual.Revision != controlledRoot.Entry.Revision {
		t.Fatal("unavailable child changed source collection")
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var created, published, attrs, commands, accepts, intents, runs int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathCreated'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathPublished'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathAttrsChanged'),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&created, &published, &attrs, &commands, &accepts, &intents, &runs); err != nil || created != 3 || published != 2 || attrs != 3 || commands != 2 || accepts != 0 || intents != 0 || runs != 0 {
		t.Fatal("copy lost exact creation/property events/private receipts or caused unrelated effects", created, published, attrs, commands, accepts, intents, runs, err)
	}
}
