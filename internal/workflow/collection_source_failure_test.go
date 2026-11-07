package workflow

import (
	"errors"
	"testing"
)

func TestRefusedCollectionSourceDoesNotReturnACleanupHandleOrPanic(t *testing.T) {
	local, _ := localConnectionContract(t)
	ftps := ftpsConnectionContract()
	for _, c := range []struct {
		kind       string
		definition ConnectionDefinition
	}{
		{"sftp.collect", ConnectionDefinition{Schema: 1, Directory: "/"}},
		{"ftps.collect", ftps},
		{"local.collect", local},
	} {
		t.Run(c.kind, func(t *testing.T) {
			denied := errors.New("synthetic current collection authority refused")
			calls := 0
			peer, err := openCollectionSourcePeer(t.Context(), &c.definition, c.kind, func() error { calls++; return denied })
			if err == nil || calls != 1 {
				t.Fatal("refused source acquired a reader or bypassed current authority", err, calls)
			}
			// Exercise the worker's actual deferred interface cleanup. A typed nil
			// pointer inside this interface is not a usable or closable reader.
			var panicValue any
			func() {
				defer func() { panicValue = recover() }()
				if peer != nil {
					_ = peer.Close()
				}
			}()
			if peer != nil || panicValue != nil {
				t.Fatal("refused source exposed a cleanup handle;cleanup panic", panicValue != nil)
			}
		})
	}
}
