package api

import (
	"encoding/json"
	"testing"
)

type davSourceAuditRow struct {
	Hash, Actor, Kind, Resource string
	Payload                     json.RawMessage
}

type davSourceReadBinding struct{ Actor, File, SHA256 string }

// Preserve every old journal row and admit exactly the expected immutable read
// authorization events. File/mapping/credential/command state is checked apart.
func davSourceReadAuditsMatch(before, after map[string]davSourceAuditRow, expected map[davSourceReadBinding]int) bool {
	remaining := map[davSourceReadBinding]int{}
	for binding, count := range expected {
		if count < 0 {
			return false
		}
		remaining[binding] = count
	}
	for id, row := range before {
		current, exists := after[id]
		if !exists || row.Hash == "" || current.Hash != row.Hash {
			return false
		}
	}
	for id, row := range after {
		if _, exists := before[id]; exists {
			continue
		}
		if row.Hash == "" || row.Kind != "FileDownloadAuthorized" {
			return false
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(row.Payload, &fields) != nil || len(fields) != 2 {
			return false
		}
		var hash, session string
		if json.Unmarshal(fields["sha256"], &hash) != nil || json.Unmarshal(fields["protocol_session_id"], &session) != nil || session != "" {
			return false
		}
		binding := davSourceReadBinding{Actor: row.Actor, File: row.Resource, SHA256: hash}
		if remaining[binding] < 1 {
			return false
		}
		remaining[binding]--
	}
	for _, count := range remaining {
		if count != 0 {
			return false
		}
	}
	return true
}

func TestDAVReadOnlySourceKeepsExactRequiredAuditAndRefusesHiddenMutation(t *testing.T) {
	old := davSourceAuditRow{Hash: "unchanged-original-event", Actor: "owner", Kind: "PathPublished", Resource: "source"}
	read := davSourceAuditRow{Hash: "new-immutable-read-event", Actor: "reader", Kind: "FileDownloadAuthorized", Resource: "file", Payload: json.RawMessage(`{"sha256":"expected-file-hash","protocol_session_id":""}`)}
	before := map[string]davSourceAuditRow{"old": old}
	valid := map[string]davSourceAuditRow{"old": old, "read": read}
	expected := map[davSourceReadBinding]int{{Actor: "reader", File: "file", SHA256: "expected-file-hash"}: 1}
	if !davSourceReadAuditsMatch(before, valid, expected) {
		t.Fatal("original zero-event rule refuses the producer's mandatory exact read audit")
	}
	for _, mutate := range []func(map[string]davSourceAuditRow){
		func(rows map[string]davSourceAuditRow) { v := rows["old"]; v.Hash = "changed"; rows["old"] = v },
		func(rows map[string]davSourceAuditRow) { delete(rows, "old") },
		func(rows map[string]davSourceAuditRow) { v := rows["read"]; v.Kind = "PathRemoved"; rows["read"] = v },
		func(rows map[string]davSourceAuditRow) { v := rows["read"]; v.Actor = "other"; rows["read"] = v },
		func(rows map[string]davSourceAuditRow) { v := rows["read"]; v.Resource = "other"; rows["read"] = v },
		func(rows map[string]davSourceAuditRow) {
			v := rows["read"]
			v.Payload = json.RawMessage(`{"sha256":"other","protocol_session_id":""}`)
			rows["read"] = v
		},
		func(rows map[string]davSourceAuditRow) {
			v := rows["read"]
			v.Payload = json.RawMessage(`{"sha256":"expected-file-hash","protocol_session_id":"","forward":true}`)
			rows["read"] = v
		},
		func(rows map[string]davSourceAuditRow) { rows["extra"] = rows["read"] },
		func(rows map[string]davSourceAuditRow) { delete(rows, "read") },
		func(rows map[string]davSourceAuditRow) {
			v := rows["read"]
			v.Payload = json.RawMessage(`{"sha256":"expected-file-hash","protocol_session_id":"other"}`)
			rows["read"] = v
		},
	} {
		changed := map[string]davSourceAuditRow{}
		for id, row := range valid {
			changed[id] = row
		}
		mutate(changed)
		if davSourceReadAuditsMatch(before, changed, expected) {
			t.Fatal("changed,missing,extra,unbound or non-read event accepted")
		}
	}
}
