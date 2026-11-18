//go:build integration

package main

import (
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

func qualifyPortableExchangeTrace(t *testing.T, actor, token, unrelated string, live store.ExchangeTrace,
	command func(string, string, ...string) ([]byte, error), requestFile func(any) string) {
	t.Helper()
	selected := store.ExchangeTraceExportSelection{
		ExchangeTraceRequest: store.ExchangeTraceRequest{ID: live.ID, Direction: live.Direction}, RequestHash: live.RequestHash,
	}
	if live.Profile != store.ExchangeEvidenceV1 {
		selected.Profile = live.Profile
	}
	path := filepath.Join(privateCLIDirectory(t), "exchange-evidence.json")
	input := requestFile(selected)
	refuse := func(as string, selection store.ExchangeTraceExportSelection, want error) {
		t.Helper()
		if raw, err := command(as, "exchange-trace-export", "--request-file", requestFile(selection), "--output", path); !errors.Is(err, want) || len(raw) != 0 {
			t.Fatal("portable exchange returned evidence outside the chosen authorization and hash", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("refused exchange export published a file", err)
		}
	}
	refuse(unrelated, selected, store.ErrNotFound)
	wrong := selected
	wrong.RequestHash = strings.Repeat("0", 64)
	refuse(token, wrong, store.ErrRevision)
	wrong = selected
	if live.Direction == "incoming" {
		wrong.Direction = "outgoing"
	} else {
		wrong.Direction = "incoming"
	}
	refuse(token, wrong, store.ErrNotFound)
	raw, err := command(token, "exchange-trace-export", "--request-file", input, "--output", path)
	var receipt custody.ExchangeTraceExportReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil || receipt.Source != selected {
		t.Fatal("scoped exchange export has no exact receipt", err)
	}
	requireSealedCLIOutput(t, path)
	body, err := os.ReadFile(path)
	var portable custody.PortableExchangeTrace
	if err != nil || secure.Digest(body) != receipt.SHA256 || len(body) != receipt.Size ||
		json.Unmarshal(body, &portable) != nil || portable.Profile != custody.PortableExchangeTraceProfile ||
		portable.SourceActor != actor || portable.Source != selected || portable.Evidence == nil {
		t.Fatal("published artifact differs from the prepared exchange receipt", err)
	}
	if !reflect.DeepEqual(portable.Evidence.Events, live.Events) ||
		portable.Evidence.Profile != live.Profile || !reflect.DeepEqual(portable.Evidence.Projection, live.Projection) ||
		!reflect.DeepEqual(portable.Evidence.ReceivedCopy, live.ReceivedCopy) ||
		!reflect.DeepEqual(portable.Evidence.IntegrityReport, live.IntegrityReport) ||
		portable.Evidence.State != live.State || portable.Evidence.Artifact == nil || *portable.Evidence.Artifact != *live.Artifact ||
		portable.Evidence.ReceiverPersistence != "unknown" || portable.Evidence.Retrieval != "unknown" ||
		portable.Evidence.BusinessProcessing != "unknown" || portable.Evidence.StorageVerification != "not-checked" {
		t.Fatal("export weakened the source event or outcome distinctions")
	}
	t.Logf("%s exchange evidence %s, %d original event references", live.Direction, receipt.SHA256, len(live.Events))
}
