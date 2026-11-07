//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/namespaceprops"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestWebDAVPropertiesAreAtomicRevisionBoundPrivateAndPreservedAcrossMappings(t *testing.T) {
	service, scope, admin, server := browserAPI(t, time.Minute)
	cookie, csrf := loginBrowser(t, server, scope, admin)
	prefix := "/v1/tenants/" + scope.Tenant + "/partners/" + scope.Partner
	data := []byte("immutable property owner payload\n")
	_, raw := exchangeAPIRequest(t, server, "PUT", prefix+"/namespace/file?path=/properties.dat", nil, map[string]string{"Authorization": "Bearer " + string(admin.Bytes), "Idempotency-Key": "properties-source", "X-File-Size": strconv.Itoa(len(data)), "X-Content-SHA256": secure.Digest(data)}, data, 201)
	var accepted struct {
		File store.File `json:"file"`
	}
	if json.Unmarshal(raw, &accepted) != nil {
		t.Fatal("source missing")
	}
	entry, err := service.StatPath(t.Context(), scope, "/properties.dat")
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0660)
	shared, err := service.PathCommand(t.Context(), scope, "properties-explicit-shared-mode", store.PathCommand{Operation: "setstat", Path: entry.Path, ExpectedRevision: &entry.Revision, Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	entry = &shared.Entry
	operator, participant := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write", "manage_paths"})
	otherManager, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write", "manage_paths"})
	reader, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "manage_paths"})
	writer, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"write", "list", "manage_paths"})
	nonmanager, _ := exchangeAPIParticipant(t, server, prefix, cookie, csrf, []string{"read", "list", "write"})
	condition := entry.ID + ":" + strconv.FormatInt(entry.Revision, 10)
	headers := func(token *secure.Secret, key, revision string) map[string]string {
		return map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Content-Type": "application/xml", "Idempotency-Key": key, "X-Freightctl-Namespace-Revision": revision}
	}
	update := []byte(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example" xmlns:q="urn:types" xml:lang="fr"><set><prop><x:label>été <q:value q:type="q:Label">data &amp; only</q:value> tail q:Label</x:label><x:execute approved="true">never grants authority</x:execute></prop></set><remove><prop><x:absent/></prop></remove></propertyupdate>`)
	target := prefix + "/dav/properties.dat"
	for _, token := range []*secure.Secret{reader, writer, nonmanager} {
		exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(token, "properties-denied", condition), update, 403)
	}
	response, _ := exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-original", condition), update, 207)
	current, err := service.StatPath(t.Context(), scope, entry.Path)
	if err != nil || current.ID != entry.ID || current.FileID != entry.FileID || current.Revision != entry.Revision+1 || current.Mode != entry.Mode || !current.Modified.Equal(entry.Modified) || response.Header.Get("ETag") != "" || response.Header.Get("X-Freightctl-Namespace-Revision") != current.ID+":"+strconv.FormatInt(current.Revision, 10) {
		t.Fatal("property mutation changed custody,mode,time or wrong revision", err)
	}
	read := func(path string, token *secure.Secret) []byte {
		t.Helper()
		response, body := exchangeAPIRequest(t, server, "PROPFIND", prefix+"/dav"+path, nil, map[string]string{"Authorization": "Bearer " + string(token.Bytes), "Depth": "0", "Content-Type": "application/xml"}, []byte(`<propfind xmlns="DAV:"><allprop/></propfind>`), 207)
		if response.Header.Get("Content-Security-Policy") != "default-src 'none'; sandbox" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("untrusted property data lost browser execution isolation")
		}
		var doc struct {
			Responses []struct {
				Groups []struct {
					Prop struct {
						Label struct {
							Text  string `xml:",chardata"`
							Value string `xml:"urn:types value"`
						} `xml:"urn:example label"`
						Execute  string `xml:"urn:example execute"`
						EntryID  string `xml:"urn:freightctl:namespace entry-id"`
						Revision int64  `xml:"urn:freightctl:namespace revision"`
					} `xml:"DAV: prop"`
				} `xml:"DAV: propstat"`
			} `xml:"DAV: response"`
		}
		if xml.Unmarshal(body, &doc) != nil || len(doc.Responses) != 1 || len(doc.Responses[0].Groups) != 1 {
			t.Fatal("property response not complete")
		}
		p := doc.Responses[0].Groups[0].Prop
		if p.Label.Text != "été  tail q:Label" || p.Label.Value != "data & only" || p.Execute != "never grants authority" || !store.ValidID(p.EntryID) || p.Revision < 1 || !bytes.Contains(body, []byte(`xml:lang="fr"`)) || !bytes.Contains(body, []byte(`xmlns:q="urn:types"`)) {
			t.Fatal("property XML or explicit namespace identity changed")
		}
		return body
	}
	read(entry.Path, operator)
	// Another equally privileged actor cannot recover this actor's receipt.
	exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(otherManager, "properties-original", condition), update, 412)
	_, raw = exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-original", condition), update, 200)
	var receipt struct {
		Result store.PathResult `json:"result"`
		State  string           `json:"namespace_state"`
	}
	if json.Unmarshal(raw, &receipt) != nil || !receipt.Result.Replayed || receipt.State != "not-asserted-original-receipt" {
		t.Fatal("property replay repeated effects or asserted current state")
	}
	exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-stale", condition), update, 412)
	changed := bytes.Replace(update, []byte("never grants authority"), []byte("different meaning"), 1)
	exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-original", condition), changed, 409)
	protected := []byte(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><set><prop><x:label>partial must not survive</x:label><getetag>fake</getetag></prop></set></propertyupdate>`)
	exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-protected", current.ID+":"+strconv.FormatInt(current.Revision, 10)), protected, 403)
	read(entry.Path, operator)
	// Raw property data does not enter ordinary stat responses or typed receipts.
	_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/namespace/stat?path=/properties.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
	if bytes.Contains(raw, []byte("property_xml")) || bytes.Contains(raw, []byte("namespace_properties")) || bytes.Contains(raw, []byte("never grants authority")) {
		t.Fatal("ordinary metadata acquired property content")
	}
	operatorScope := store.Scope{Tenant: scope.Tenant, Partner: scope.Partner, TokenHash: secure.Digest(operator.Bytes)}
	copyResult, err := service.CopyFileIfCurrent(t.Context(), operatorScope, "properties-copy", entry.Path, "/copy.dat", accepted.File.ID, accepted.File.SHA256)
	if err != nil || copyResult.Entry.ID == entry.ID {
		t.Fatal("independent property copy failed", err)
	}
	read("/copy.dat", operator)
	if _, err = service.MoveFileIfCurrent(t.Context(), operatorScope, "properties-move", entry.Path, "/moved.dat", accepted.File.ID, accepted.File.SHA256); err != nil {
		t.Fatal(err)
	}
	read("/moved.dat", operator)
	exchangeAPIRequest(t, server, "PROPPATCH", target, nil, headers(operator, "properties-original", condition), update, 412)
	// Editing the distinct copy does not mutate the source property's value.
	remove := []byte(`<propertyupdate xmlns="DAV:" xmlns:x="urn:example"><remove><prop><x:label/><x:execute/></prop></remove></propertyupdate>`)
	exchangeAPIRequest(t, server, "PROPPATCH", prefix+"/dav/copy.dat", nil, headers(operator, "properties-remove", copyResult.Entry.ID+":1"), remove, 207)
	read("/moved.dat", operator)
	_, raw = exchangeAPIRequest(t, server, "PROPFIND", prefix+"/dav/copy.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Depth": "0"}, nil, 207)
	if bytes.Contains(raw, []byte("never grants authority")) {
		t.Fatal("dead property remove did not take effect")
	}
	for _, path := range []string{"/moved.dat", "/copy.dat"} {
		_, raw = exchangeAPIRequest(t, server, "GET", prefix+"/dav"+path, nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes)}, nil, 200)
		if !bytes.Equal(raw, data) {
			t.Fatal("metadata mutation changed immutable bytes")
		}
	}
	// A fresh non-owner runtime transaction cannot bypass the existing journal
	// guard by updating only the projection or by omitting the property snapshot.
	for _, withEvent := range []bool{false, true} {
		tx, err := service.DB.Begin(t.Context(), scope)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := tx.Entry(t.Context(), "/moved.dat")
		if err != nil {
			t.Fatal(err)
		}
		event := actual.EventID
		if withEvent {
			event, err = tx.Append(t.Context(), "PathAttrsChanged", actual.ID, map[string]any{"path": actual.Path, "kind": actual.Kind, "file_id": actual.FileID, "owner_actor_id": actual.Owner, "mode": actual.Mode, "revision": actual.Revision + 1, "previous_revision": actual.Revision, "deleted": false, "modified_unix_us": actual.Modified.UnixMicro()})
			if err != nil {
				t.Fatal(err)
			}
		}
		_, err = tx.Tx.Exec(t.Context(), `UPDATE namespace_entries SET revision=revision+1,changed_event_id=$1,namespace_properties='{}'::jsonb WHERE entry_id=$2`, event, actual.ID)
		_ = tx.Tx.Rollback(t.Context())
		if err == nil {
			t.Fatal("unjournaled property projection accepted")
		}
	}
	read("/moved.dat", operator)
	// Namespace entry identity protects directories against equal-revision ABA.
	moved, err := service.StatPath(t.Context(), scope, "/moved.dat")
	if err != nil {
		t.Fatal(err)
	}
	mode = 0000
	private, err := service.PathCommand(t.Context(), scope, "properties-private-mode", store.PathCommand{Operation: "setstat", Path: moved.Path, ExpectedRevision: &moved.Revision, Mode: &mode})
	if err != nil {
		t.Fatal(err)
	}
	// The readable independent copy cannot rescue the declared private path.
	exchangeAPIRequest(t, server, "PROPPATCH", prefix+"/dav/moved.dat", nil, headers(operator, "properties-private-refused", private.Entry.ID+":"+strconv.FormatInt(private.Entry.Revision, 10)), update, 403)
	exchangeAPIRequest(t, server, "PROPFIND", prefix+"/dav/moved.dat", nil, map[string]string{"Authorization": "Bearer " + string(operator.Bytes), "Depth": "0"}, nil, 403)
	forged := private.Entry
	forged.Mode = 0666
	readTx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := readTx.EntryProperties(t.Context(), &forged)
	_ = readTx.Tx.Rollback(t.Context())
	if !errors.Is(readErr, store.ErrForbidden) {
		t.Fatal("supplied metadata rescued a private actual property path", readErr)
	}
	mode = 0660
	if _, err = service.PathCommand(t.Context(), scope, "properties-restored-mode", store.PathCommand{Operation: "setstat", Path: moved.Path, ExpectedRevision: &private.Entry.Revision, Mode: &mode}); err != nil {
		t.Fatal(err)
	}
	read("/moved.dat", operator)
	dir, err := service.PathCommand(t.Context(), scope, "properties-dir", store.PathCommand{Operation: "mkdir", Path: "/directory"})
	if err != nil {
		t.Fatal(err)
	}
	changes, err := namespaceprops.ParseUpdate(strings.NewReader(string(update)))
	if err != nil {
		t.Fatal(err)
	}
	cmd := store.PathCommand{Operation: "properties", Path: "/directory", ExpectedEntryID: dir.Entry.ID, ExpectedRevision: &dir.Entry.Revision, PropertyChanges: changes}
	result, err := service.PathCommand(t.Context(), scope, "properties-directory", cmd)
	if err != nil {
		t.Fatal(err)
	}
	read("/directory", admin)
	if _, err = service.PathCommand(t.Context(), scope, "properties-directory-remove", store.PathCommand{Operation: "rmdir", Path: "/directory", ExpectedRevision: &result.Entry.Revision}); err != nil {
		t.Fatal(err)
	}
	newDir, err := service.PathCommand(t.Context(), scope, "properties-directory-recreate", store.PathCommand{Operation: "mkdir", Path: "/directory"})
	if err != nil || newDir.Entry.ID == dir.Entry.ID || newDir.Entry.Revision != dir.Entry.Revision {
		t.Fatal("directory ABA fixture differs", err)
	}
	exchangeAPIRequest(t, server, "PROPPATCH", prefix+"/dav/directory/", nil, headers(admin, "properties-directory-stale", fmt.Sprintf("%s:%d", dir.Entry.ID, dir.Entry.Revision)), update, 412)
	// Count only this actor's private original command receipts. Property data
	// generated no transfer intent,workflow run or custody acceptance.
	events, err := service.DB.Events(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := service.DB.SnapshotEvents(t.Context(), scope, 1000, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, safe := range []any{events, snapshot} {
		encoded, err := json.Marshal(safe)
		if err != nil || bytes.Contains(encoded, []byte("never grants authority")) || bytes.Contains(encoded, []byte("CLI inert data")) || bytes.Contains(encoded, []byte("q:Label")) {
			t.Fatal("audit permission disclosed untrusted namespace property contents", err)
		}
	}
	tx, err := service.DB.Begin(t.Context(), operatorScope)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Tx.Rollback(t.Context())
	var commands, attrs, intents, runs, accepts int
	if err = tx.Tx.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM namespace_commands),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='PathAttrsChanged'),(SELECT count(*) FROM delivery_intents),(SELECT count(*) FROM workflow_runs),(SELECT count(*) FROM events WHERE actor_id=$1 AND kind='FileAccepted')`, participant.Actor).Scan(&commands, &attrs, &intents, &runs, &accepts); err != nil || commands != 4 || attrs != 2 || intents != 0 || runs != 0 || accepts != 0 {
		t.Fatal("property authority or atomic receipt count changed", commands, attrs, intents, runs, accepts, err)
	}
}
