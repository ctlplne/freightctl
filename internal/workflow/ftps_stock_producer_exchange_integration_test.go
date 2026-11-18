//go:build integration && stockftpsproducer && (linux || darwin)

package workflow

import (
	"encoding/json"
	"os"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/delivery"
	"github.com/ctlplne/freightctl/internal/store"
)

// The qualification harness starts and observes the independent read-only
// producer. Compiling this profile without the real peer is a test failure.
func TestStockFTPSProducerToAgentAndSeparatelyApprovedStockSFTP(t *testing.T) {
	ref, err := secure.ReadSecret(os.Getenv("FREIGHTCTL_TEST_STOCK_FTPS_PRODUCER_FILE"), 4096)
	if err != nil {
		t.Fatal("the stock producer journey requires a protected connection fixture")
	}
	var dest secure.FTPSDestination
	err = json.Unmarshal(ref.Bytes, &dest)
	ref.Close()
	if err != nil || secure.ValidateFTPSDestination(dest) != nil {
		t.Fatal("invalid stock producer connection fixture")
	}
	t.Run(dest.Mode, func(t *testing.T) {
		binary := routingKeyCLI(t)
		f := setup(t)
		// The current registry shares a reference shape with outbound FTPS.
		// This fixture selects only ftps.collect, with no outbound workflow step.
		connection := registeredFTPSConnection(t, f, delivery.FTPSDefinition{
			Destination: dest, StagingDirectory: "/stage",
			ReceiverContract: store.FTPSReceiverContract{
				Schema: 1, DocumentSHA256: secure.Digest([]byte("fixture placeholder for the shared FTPS reference shape")),
				StagingVisibility: "receiver-private", Rename: "may-replace",
				Duplicates: "receiver-deduplicates-delivery-id", Receipt: "exact-readback",
			},
		})
		x := prepareFTPSCollection(t, f, connection, false, false)
		body := []byte("abc")
		manifest := &CollectionManifest{Schema: 1, Batch: "00000000-0000-4000-8000-000000000509",
			Files: []CollectionFile{{Name: "one.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}},
		}
		proveCollectionAgentOnward(t, f, x.selection, binary, body, "", manifest, nil)
	})
}
