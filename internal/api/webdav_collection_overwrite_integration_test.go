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

func TestWebDAVCollectionOverwritePinsBothTreesAndCommitsNoMergeAtomically(t *testing.T) {
	for _, profile := range []struct {
		name, method, depth string
		copied              int
	}{{"move", "MOVE", "infinity", 4}, {"copy-full", "COPY", "infinity", 4}, {"copy-shallow", "COPY", "0", 1}} {
		t.Run(profile.name, func(t *testing.T) {
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
			sharedDir, sharedFile := uint32(0770), uint32(0660)
			source := apply("overwrite-source", store.PathCommand{Operation: "mkdir", Path: "/source"})
			apply("overwrite-source-nested", store.PathCommand{Operation: "mkdir", Path: "/source/nested"})
			target := apply("overwrite-target", store.PathCommand{Operation: "mkdir", Path: "/target", Mode: &sharedDir})
			apply("overwrite-target-obsolete", store.PathCommand{Operation: "mkdir", Path: "/target/obsolete", Mode: &sharedDir})
			sourceData, oldData := []byte("complete source immutable bytes\n"), []byte("old target custody stays retained\n")
			files := map[string]*store.File{}
			for i, path := range []string{"/source/a.dat", "/source/nested/b.dat", "/target/extra.dat", "/target/obsolete/old.dat"} {
				data := sourceData
				selection := custody.UploadTarget{Path: path}
				if strings.HasPrefix(path, "/target/") {
					data = oldData
					selection.Mode = &sharedFile
				}
				f, _, err := service.AcceptAt(t.Context(), scope, "overwrite-file-"+strconv.Itoa(i), int64(len(data)), secure.Digest(data), bytes.NewReader(data), selection)
				if err != nil {
					t.Fatal(err)
				}
				files[path] = f
			}
			property := namespaceprops.Change{Operation: "set", Property: `<x:label xmlns:x="urn:example" xml:lang="fr">inert <x:execute>source data only</x:execute></x:label>`}
			for _, path := range []string{"/source", "/source/a.dat"} {
				e := stat(path)
				apply("overwrite-property-"+strings.ReplaceAll(path, "/", "-"), store.PathCommand{Operation: "properties", Path: path, ExpectedEntryID: e.ID, ExpectedRevision: &e.Revision, PropertyChanges: []namespaceprops.Change{property}})
			}
			source.Entry = stat("/source")
			permissions := []string{"read", "list", "manage_paths"}
			if profile.method == "COPY" {
				permissions = append(permissions, "write")
			}
			operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, permissions)
			noManage, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
			other, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, permissions)
			headers := func(token *secure.Secret, key string, src, dst store.PathEntry) map[string]string {
				return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Idempotency-Key": key, "X-Freightctl-Namespace-Revision": src.ID + ":" + strconv.FormatInt(src.Revision, 10), "X-Freightctl-Destination-Revision": dst.ID + ":" + strconv.FormatInt(dst.Revision, 10), "Overwrite": "T", "Depth": profile.depth, "Destination": server.URL + prefix + "/dav" + dst.Path + "/"}
			}
			paths := []string{"/source", "/source/nested", "/source/a.dat", "/source/nested/b.dat", "/target", "/target/obsolete", "/target/extra.dat", "/target/obsolete/old.dat"}
			snapshot := func() map[string]store.PathEntry {
				t.Helper()
				result := map[string]store.PathEntry{}
				for _, path := range paths {
					e := stat(path)
					e.Modified = e.Modified.UTC()
					result[path] = e
				}
				return result
			}
			unchanged := func(before map[string]store.PathEntry) {
				t.Helper()
				if !maps.Equal(before, snapshot()) {
					t.Fatal("refused overwrite changed a source or destination member")
				}
			}
			url := prefix + "/dav/source/"
			before := snapshot()
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(noManage, "overwrite-denied", source.Entry, target.Entry), nil, 403)
			unchanged(before)
			old := stat("/target/obsolete/old.dat")
			private := uint32(0600)
			protected := apply("overwrite-private", store.PathCommand{Operation: "setstat", Path: old.Path, ExpectedRevision: &old.Revision, Mode: &private})
			apply("overwrite-readable-alias", store.PathCommand{Operation: "publish", Path: "/outside-old.dat", FileID: old.FileID})
			_, alias := exchangeAPIRequest(t, server, "GET", prefix+"/dav/outside-old.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
			if !bytes.Equal(alias, oldData) {
				t.Fatal("target alias fixture differs")
			}
			before = snapshot()
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-private-refused", source.Entry, target.Entry), nil, 403)
			unchanged(before)
			readOnly := uint32(0440)
			protected = apply("overwrite-readonly", store.PathCommand{Operation: "setstat", Path: old.Path, ExpectedRevision: &protected.Entry.Revision, Mode: &readOnly})
			before = snapshot()
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-write-refused", source.Entry, target.Entry), nil, 403)
			unchanged(before)
			apply("overwrite-target-restored", store.PathCommand{Operation: "setstat", Path: old.Path, ExpectedRevision: &protected.Entry.Revision, Mode: &sharedFile})
			before = snapshot()
			stale := target.Entry
			stale.Revision++
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-stale-target", source.Entry, stale), nil, 412)
			unchanged(before)
			wrong := target.Entry
			wrong.ID = secure.NewID()
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-wrong-target", source.Entry, wrong), nil, 412)
			unchanged(before)
			missing := target.Entry
			missing.Path = "/absent-target"
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-absent-target", source.Entry, missing), nil, 412)
			unchanged(before)
			f := headers(operator, "overwrite-non-overwrite", source.Entry, target.Entry)
			f["Overwrite"] = "F"
			delete(f, "X-Freightctl-Destination-Revision")
			exchangeAPIRequest(t, server, profile.method, url, nil, f, nil, 412)
			unchanged(before)
			nested := stat("/source/nested")
			exchangeAPIRequest(t, server, profile.method, prefix+"/dav/source/nested/", nil, headers(operator, "overwrite-ancestor-refused", nested, source.Entry), nil, 403)
			unchanged(before)
			aba := apply("overwrite-aba", store.PathCommand{Operation: "mkdir", Path: "/target-aba", Mode: &sharedDir})
			apply("overwrite-aba-remove", store.PathCommand{Operation: "rmdir", Path: aba.Entry.Path, ExpectedRevision: &aba.Entry.Revision})
			recreated := apply("overwrite-aba-recreate", store.PathCommand{Operation: "mkdir", Path: aba.Entry.Path, Mode: &sharedDir})
			if recreated.Entry.ID == aba.Entry.ID || recreated.Entry.Revision != aba.Entry.Revision {
				t.Fatal("target ABA fixture is not exact")
			}
			exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-aba-refused", source.Entry, aba.Entry), nil, 412)
			unchanged(before)
			limit := service.NamespaceMaxEntries
			t.Cleanup(func() { service.NamespaceMaxEntries = limit })
			if profile.method == "COPY" {
				service.NamespaceMaxEntries = 1
				exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-capacity-refused", source.Entry, target.Entry), nil, 507)
				unchanged(before)
				tx, err := service.DB.Begin(t.Context(), scope)
				if err != nil {
					t.Fatal(err)
				}
				var total int
				if err = tx.Tx.QueryRow(t.Context(), `SELECT count(*) FROM namespace_entries WHERE NOT deleted`).Scan(&total); err != nil {
					t.Fatal(err)
				}
				if err = tx.Tx.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}
				service.NamespaceMaxEntries = total // Lower the test quota;replacement must fit at this full limit.
			}
			original := headers(operator, "overwrite-original", source.Entry, target.Entry)
			response, raw := exchangeAPIRequest(t, server, profile.method, url, nil, original, nil, 204)
			service.NamespaceMaxEntries = limit
			if len(raw) != 0 || response.Header.Get("X-Freightctl-Namespace-State") != "collection-replaced-at-commit" || response.Header.Get("X-Freightctl-Changed-Entries") != strconv.Itoa(profile.copied+4) || !store.ValidID(response.Header.Get("X-Freightctl-Event-ID")) || response.Header.Get("ETag") != "" || response.Header.Get("Location") != "" {
				t.Fatal("collection overwrite lost exact atomic no-content outcome")
			}
			current := stat("/target")
			if current.ID == target.Entry.ID || (profile.method == "MOVE" && current.ID != source.Entry.ID) || (profile.method == "COPY" && current.ID == source.Entry.ID) {
				t.Fatal("overwrite merged or reused the wrong resource identity")
			}
			props, err := service.ReadNamespacePropertySnapshot(t.Context(), scope, "/target")
			if err != nil || props.Properties["{urn:example}label"] != property.Property {
				t.Fatal("overwrite lost inert root properties", err)
			}
			for _, path := range []string{"/target/obsolete", "/target/extra.dat", "/target/obsolete/old.dat"} {
				if _, err = service.StatPath(t.Context(), scope, path); !errors.Is(err, store.ErrNotFound) {
					t.Fatal("collection overwrite merged an old target member", err)
				}
			}
			for _, path := range []string{"/source/a.dat", "/source/nested/b.dat"} {
				destination := "/target" + strings.TrimPrefix(path, "/source")
				if profile.copied == 1 {
					if _, err = service.StatPath(t.Context(), scope, destination); !errors.Is(err, store.ErrNotFound) {
						t.Fatal("shallow overwrite copied a source child", err)
					}
				} else {
					response, data := exchangeAPIRequest(t, server, "GET", prefix+"/dav"+destination, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
					if !bytes.Equal(data, sourceData) || response.Header.Get("X-File-Revision-ID") != files[path].ID {
						t.Fatal("overwritten member custody differs")
					}
				}
			}
			for _, path := range []string{"/target/extra.dat", "/target/obsolete/old.dat"} {
				_, data := exchangeAPIRequest(t, server, "GET", prefix+"/files/"+files[path].ID, nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes)}, nil, 200)
				if !bytes.Equal(data, oldData) {
					t.Fatal("overwrite erased retained old custody")
				}
			}
			if profile.method == "MOVE" {
				for _, path := range paths[:4] {
					if _, err = service.StatPath(t.Context(), scope, path); !errors.Is(err, store.ErrNotFound) {
						t.Fatal("overwrite MOVE retained an old source member", err)
					}
				}
				exchangeAPIRequest(t, server, profile.method, url, nil, original, nil, 412)
			} else {
				for _, path := range paths[:4] {
					e := stat(path)
					e.Modified = e.Modified.UTC()
					if e != before[path] {
						t.Fatal("overwrite COPY changed source metadata")
					}
				}
				response, raw = exchangeAPIRequest(t, server, profile.method, url, nil, original, nil, 200)
				var history struct {
					Result store.PathResult `json:"result"`
					State  string           `json:"namespace_state"`
				}
				if json.Unmarshal(raw, &history) != nil || !history.Result.Replayed || history.State != "not-asserted-original-receipt" || response.Header.Get("Location") != "" {
					t.Fatal("overwrite COPY receipt repeated or asserted current destination")
				}
				exchangeAPIRequest(t, server, profile.method, url, nil, headers(other, "overwrite-original", source.Entry, target.Entry), nil, 412)
				exchangeAPIRequest(t, server, profile.method, url, nil, headers(operator, "overwrite-original", source.Entry, current), nil, 409)
			}
			op := "move_tree"
			if profile.method == "COPY" {
				op = "copy_tree"
				if profile.depth == "0" {
					op = "copy_dir"
				}
			}
			selection := store.PathCommand{Operation: op, Path: "/source", Target: "/target", ExpectedEntryID: source.Entry.ID, ExpectedRevision: &source.Entry.Revision, Replace: true, TargetEntryID: target.Entry.ID, TargetRevision: &target.Entry.Revision}
			_, raw = exchangeAPIRequest(t, server, "POST", prefix+"/namespace/receipts", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "overwrite-original"}, exchangeAPIJSON(t, selection), 200)
			var receipt store.PathCommandReceipt
			if json.Unmarshal(raw, &receipt) != nil || receipt.Observation != "original-commit-not-current-state" || receipt.Result.Changed != profile.copied+4 || receipt.Result.Entry.ID != current.ID || receipt.Result.Replayed {
				t.Fatal("overwrite lost its exact private original receipt")
			}
			actorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
			tx, err := service.DB.Begin(t.Context(), actorScope)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Tx.Rollback(t.Context())
			var removed, moved, created, published, attrs, commands, accepts, intents, runs int
			if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathRemoved'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathMoved'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathCreated'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathPublished'),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathAttrsChanged'),(SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs)`, participant.Actor).Scan(&removed, &moved, &created, &published, &attrs, &commands, &accepts, &intents, &runs); err != nil {
				t.Fatal(err)
			}
			wantMoved, wantCreated, wantPublished, wantAttrs := 4, 0, 0, 0
			if profile.method == "COPY" {
				wantMoved = 0
				wantCreated = 2
				wantPublished = 2
				wantAttrs = 1
				if profile.copied == 1 {
					wantCreated = 1
					wantPublished = 0
				}
			}
			if removed != 4 || moved != wantMoved || created != wantCreated || published != wantPublished || attrs != wantAttrs || commands != 1 || accepts != 0 || intents != 0 || runs != 0 {
				t.Fatal("overwrite lost atomic exact member events/private receipt or gained unrelated effects", removed, moved, created, published, attrs, commands, accepts, intents, runs)
			}
		})
	}
}

func TestWebDAVCollectionOverwriteCannotRemoveAnUnavailableTargetMember(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	mode := uint32(0770)
	source, err := service.PathCommand(t.Context(), scope, "policy-overwrite-source", store.PathCommand{Operation: "mkdir", Path: "/policy-source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := service.PathCommand(t.Context(), scope, "policy-overwrite-target", store.PathCommand{Operation: "mkdir", Path: "/policy-target", Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	checking := &checks.Service{Custody: service}
	if _, err = checking.Register(t.Context(), scope, "policy-overwrite-definition", checks.PolicyRequest{Definition: checks.Policy{Schema: 1, Kind: "csv", Columns: []checks.Column{{Name: "record", Type: "text", Required: true}}}}); err != nil {
		t.Fatal(err)
	}
	data := []byte("record\nreleased target then revoked\n")
	fileMode := uint32(0660)
	file, _, err := service.AcceptAt(t.Context(), scope, "policy-overwrite-file", int64(len(data)), secure.Digest(data), bytes.NewReader(data), custody.UploadTarget{Path: "/policy-target/input.csv", Mode: &fileMode})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Run(t.Context(), scope, file.ID, "policy-overwrite-check"); err != nil {
		t.Fatal(err)
	}
	checked, err := checking.Get(t.Context(), scope, file.ID)
	if err != nil || checked.Check.State != "passed" {
		t.Fatal("target policy fixture not checked", err)
	}
	if _, err = checking.Release(t.Context(), scope, file.ID, "policy-overwrite-release", checks.ReleaseDecision{SHA256: file.SHA256, PolicyHash: checked.Check.PolicyHash, ReportHash: checked.Check.ReportHash, Revision: checked.Check.Revision}); err != nil {
		t.Fatal(err)
	}
	before, err := service.StatPath(t.Context(), scope, "/policy-target/input.csv")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := checking.Policy(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = checking.Revoke(t.Context(), scope, "policy-overwrite-revoke", checks.PolicyDecision{Hash: policy.Hash, Version: policy.Version, Revision: policy.Revision}); err != nil {
		t.Fatal(err)
	}
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write", "manage_paths"})
	for _, method := range []string{"MOVE", "COPY"} {
		headers := map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Idempotency-Key": "policy-overwrite-" + strings.ToLower(method), "Overwrite": "T", "X-Freightctl-Namespace-Revision": source.Entry.ID + ":" + strconv.FormatInt(source.Entry.Revision, 10), "X-Freightctl-Destination-Revision": target.Entry.ID + ":" + strconv.FormatInt(target.Entry.Revision, 10), "Destination": server.URL + prefix + "/dav/policy-target/"}
		exchangeAPIRequest(t, server, method, prefix+"/dav/policy-source/", nil, headers, nil, 409)
		for _, want := range []store.PathEntry{source.Entry, target.Entry, *before} {
			actual, err := service.StatPath(t.Context(), scope, want.Path)
			if err != nil || actual.ID != want.ID || actual.Revision != want.Revision || actual.FileID != want.FileID || actual.Mode != want.Mode || !actual.Modified.Equal(want.Modified) {
				t.Fatal("unavailable target member caused a partial overwrite", err)
			}
		}
	}
	actorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	tx, err := service.DB.Begin(t.Context(), actorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var transitions, commands int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM events WHERE actor_id=$1 AND kind IN ('PathRemoved','PathMoved','PathCreated','PathPublished','PathAttrsChanged')),(SELECT count(*) FROM namespace_commands)`, participant.Actor).Scan(&transitions, &commands); err != nil || transitions != 0 || commands != 0 {
		t.Fatal("unavailable target overwrite left transitions or private receipts", transitions, commands, err)
	}
}
