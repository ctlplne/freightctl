package ftpsclient

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMetadataBoundsRefuseBeforeAnyConnectionAccess(t *testing.T) {
	// A zero client has no transport. Invalid requests must return before
	// attempting an authority check, command, allocation or connection access.
	var client Client
	for _, request := range []struct {
		name string
		max  int64
	}{{"/manifest.ready.json", 0}, {"/manifest.ready.json", -1}, {"/manifest.ready.json", MaxMetadata + 1}, {"/../escape", 1}, {"/", 1}, {"/manifest\r\nRETR /other", 1}, {"/.freightctl/private", 1}} {
		if data, err := client.ReadBounded(request.name, request.max); !errors.Is(err, ErrInput) || data != nil {
			t.Fatal("invalid metadata request reached transport", err)
		}
	}
}

func TestMetadataReadsExposeOnlyCompleteBoundedControlBoundBytes(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		for _, kind := range []string{"exact", "empty", "maximum", "oversize", "short", "grew", "lost-completion", "unclean-tls", "foreign-data", "revoked"} {
			mode := "explicit"
			if implicit {
				mode = "implicit"
			}
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f := newFixture(t, implicit)
				body := []byte("{\"untrusted\":\"manifest data\"}")
				maximum := MaxMetadata
				var revoked atomic.Bool
				switch kind {
				case "empty":
					body = []byte{}
				case "maximum":
					body = bytes.Repeat([]byte{'x'}, int(MaxMetadata))
				case "oversize":
					maximum = int64(len(body) - 1)
				case "short", "grew":
					reported := int64(len(body))
					if kind == "short" {
						reported++
					} else {
						reported--
					}
					f.reportedSize = &reported
				case "lost-completion":
					f.drop = true
				case "unclean-tls":
					f.unclean = true
				case "foreign-data":
					f.fresh = true
				case "revoked":
					f.afterRetrieve = func() { revoked.Store(true) }
				}
				f.files["/batch.ready.json"] = body
				f.start()
				client, err := New(context.Background(), f.d, func() error {
					if revoked.Load() {
						return ErrAuthority
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				got, err := client.ReadBounded("/batch.ready.json", maximum)
				success := kind == "exact" || kind == "empty" || kind == "maximum"
				if success {
					if err != nil || !bytes.Equal(got, body) {
						t.Fatal("complete metadata differs", err)
					}
				} else if err == nil || got != nil {
					t.Fatal("incomplete or unauthorized metadata escaped", err)
				}
				if kind == "lost-completion" && !errors.Is(err, ErrCompletionUnknown) {
					t.Fatal("missing completion was invented", err)
				}
				if kind == "revoked" && !errors.Is(err, ErrAuthority) {
					t.Fatal("metadata escaped current authority", err)
				}
				f.mu.Lock()
				verbs := append([]string(nil), f.verbs...)
				unchanged := bytes.Equal(f.files["/batch.ready.json"], body)
				files := len(f.files)
				resumed := f.resumed
				f.mu.Unlock()
				if !unchanged || files != 1 {
					t.Fatal("metadata reading mutated the source")
				}
				for _, verb := range verbs {
					if strings.Contains(" STOR APPE DELE RNFR RNTO REST PORT EPRT ", " "+verb+" ") {
						t.Fatal("metadata read acquired a mutation/resume/active operation", verb)
					}
				}
				if kind == "oversize" && (strings.Contains(strings.Join(verbs, " "), "RETR") || strings.Contains(strings.Join(verbs, " "), "EPSV")) {
					t.Fatal("oversize metadata opened a data stream")
				}
				if success {
					if resumed != 1 {
						t.Fatal("metadata data-channel did not resume its own control", resumed)
					}
					expected := []string{"USER", "PASS", "PBSZ", "PROT", "TYPE", "SIZE", "EPSV", "RETR"}
					if !implicit {
						expected = append([]string{"AUTH"}, expected...)
					}
					if !reflect.DeepEqual(verbs, expected) {
						t.Fatal("metadata command contract changed", verbs)
					}
				}
			})
		}
	}
}
