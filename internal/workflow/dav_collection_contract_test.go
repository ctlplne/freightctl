package workflow

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func davConnectionContractRow(t *testing.T) *store.Configuration {
	t.Helper()
	ca, _ := json.Marshal(filepath.Join(os.TempDir(), "freightctl-dav-contract", "ca.pem"))
	token, _ := json.Marshal(filepath.Join(os.TempDir(), "freightctl-dav-contract", "token"))
	raw := fmt.Sprintf(`{"schema_version":4,"destination":{"address":"","user":"","host":{"Wire":null,"Fingerprint":""},"key_reference":"","key_fingerprint":""},"directory":"/inbox","dav":{"schema_version":1,"destination":{"address":"127.0.0.1:9443","server_name":"localhost","ca_reference":%s,"ca_sha256":"%s","token_reference":%s,"token_sha256":"%s"}}}`, ca, strings.Repeat("a", 64), token, strings.Repeat("b", 64))
	return &store.Configuration{ID: "00000000-0000-0000-0000-000000000001", Version: 1, Hash: secure.Digest([]byte(raw)), Definition: json.RawMessage(raw), State: "active", Revision: 1}
}

func TestDAVCollectionUsesExactReviewedReadOnlyConnection(t *testing.T) {
	source := collectionTestSource()
	source.Kind = "webdav.collect"
	if err := normalizeCollectionSource(source); err != nil {
		t.Fatal("reviewed outbound DAV collection is unavailable", err)
	}
	row := davConnectionContractRow(t)
	source.Connection = Reference{ID: row.ID, Version: row.Version, Hash: row.Hash}
	d, v, err := collectionSourceConnection(source, row)
	if err != nil || d.Schema != 4 || v.Protocol != "webdav" || v.Directory != "/inbox" || v.HostFingerprint != "" || v.KeyFingerprint != "" {
		t.Fatal("DAV source lost its exact reviewed protocol/connection", err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"token_reference\"", "token_sha256", strings.Repeat("b", 64), "freightctl-dav-contract", "key_reference"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("DAV connection view exposed protected credential material or references")
		}
	}
	for _, kind := range []string{"sftp.collect", "ftps.collect", "local.collect"} {
		changed := source
		changed.Kind = kind
		if _, _, err := collectionSourceConnection(changed, row); err == nil {
			t.Fatal("DAV read authority was reinterpreted as another protocol")
		}
	}
	row.State = "revoked"
	if _, _, err := collectionSourceConnection(source, row); err != store.ErrState {
		t.Fatal("revoked DAV collection connection was accepted", err)
	}
	scheduled := source
	scheduled.Contract, scheduled.Manifest = ScheduledCollectionContract, "batch-{due_utc}.ready.json"
	if normalizeCollectionSource(scheduled) == nil || validScheduleSource(ScheduleSourceSelection{Kind: "webdav.collect", Pattern: scheduled.Manifest}) {
		t.Fatal("manual DAV source gained unqualified calendar arrival authority")
	}
}
