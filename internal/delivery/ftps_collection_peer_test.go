package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/ftpsclient"
)

type readOnlyFTPSStandIn struct {
	read   func(string, int64) ([]byte, error)
	copy   func(string, io.Writer, int64, string) error
	reads  atomic.Int32
	copies atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func (f *readOnlyFTPSStandIn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}
func (f *readOnlyFTPSStandIn) ReadBounded(name string, limit int64) ([]byte, error) {
	f.reads.Add(1)
	return f.read(name, limit)
}
func (f *readOnlyFTPSStandIn) RetrieveToStage(name string, output io.Writer, size int64, digest string) error {
	f.copies.Add(1)
	return f.copy(name, output, size, digest)
}

func collectionPeerStandIn() (*FTPSCollectionPeer, *readOnlyFTPSStandIn) {
	f := &readOnlyFTPSStandIn{closed: make(chan struct{})}
	return &FTPSCollectionPeer{client: f, directory: "/approved"}, f
}

func TestFTPSCollectionConstructorRefusesBeforeAnyNetwork(t *testing.T) {
	for _, directory := range []string{"relative", "/../other", "/approved/", "/.freightctl/private"} {
		if _, err := OpenFTPSCollectionPeer(context.Background(), secure.FTPSDestination{}, directory, func() error { t.Fatal("invalid path checked authority"); return nil }); !errors.Is(err, ErrInput) {
			t.Fatal("invalid path reached transport", err)
		}
	}
	if _, err := OpenFTPSCollectionPeer(context.Background(), secure.FTPSDestination{}, "/approved", nil); !errors.Is(err, ErrInput) {
		t.Fatal("missing live authority reached transport", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenFTPSCollectionPeer(ctx, secure.FTPSDestination{}, "/approved", func() error { t.Fatal("cancelled constructor checked authority"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled constructor reached transport", err)
	}
	if _, err := OpenFTPSCollectionPeer(context.Background(), secure.FTPSDestination{}, "/approved", func() error { return ErrInput }); !errors.Is(err, ftpsclient.ErrAuthority) {
		t.Fatal("revoked constructor reached transport", err)
	}
}

func TestFTPSCollectionManifestKeepsExactApprovedPathAndOperationGuard(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	body := []byte("untrusted manifest")
	fake.read = func(name string, limit int64) ([]byte, error) {
		if name != "/approved/batch.ready.json" || limit != 32<<10 {
			t.Fatal("manifest scope changed")
		}
		return body, nil
	}
	checks := 0
	data, err := peer.ReadManifest(context.Background(), "batch.ready.json", func() error { checks++; return nil })
	if err != nil || !bytes.Equal(data, body) || checks != 2 || fake.reads.Load() != 1 {
		t.Fatal("manifest guard or exact bytes lost", err)
	}
}

func TestFTPSCollectionRefusesInvalidNamesAndClaimsBeforeReading(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	for _, name := range []string{"", "../other", "/other", "nested/name", "name\r\nRETR other"} {
		if data, err := peer.ReadManifest(context.Background(), name, func() error { return nil }); !errors.Is(err, ErrInput) || data != nil {
			t.Fatal("unsafe manifest reached reader", err)
		}
	}
	for _, digest := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("z", 64)} {
		if err := peer.CopyVerified(context.Background(), "one.csv", 3, digest, io.Discard, func() error { return nil }); !errors.Is(err, ErrInput) {
			t.Fatal("invalid digest reached reader", err)
		}
	}
	for _, size := range []int64{-1, ftpsclient.MaxFile + 1} {
		if err := peer.CopyVerified(context.Background(), "one.csv", size, secure.Digest([]byte("abc")), io.Discard, func() error { return nil }); !errors.Is(err, ErrInput) {
			t.Fatal("invalid size reached reader", err)
		}
	}
	if data, err := peer.ReadManifest(context.Background(), "batch.ready.json", nil); !errors.Is(err, ErrInput) || data != nil {
		t.Fatal("missing manifest guard admitted", err)
	}
	if err := peer.CopyVerified(context.Background(), "one.csv", 3, secure.Digest([]byte("abc")), io.Discard, nil); !errors.Is(err, ErrInput) {
		t.Fatal("missing payload guard admitted", err)
	}
	if err := peer.CopyVerified(context.Background(), "one.csv", 3, secure.Digest([]byte("abc")), nil, func() error { return nil }); !errors.Is(err, ErrInput) {
		t.Fatal("missing staging admitted", err)
	}
	if fake.reads.Load() != 0 || fake.copies.Load() != 0 {
		t.Fatal("invalid claim reached transport")
	}
}

func TestFTPSCollectionManifestNeverReturnsRevokedOrOversizedBytes(t *testing.T) {
	for _, kind := range []string{"revoked-before", "revoked-after", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			peer, fake := collectionPeerStandIn()
			body := []byte("private manifest")
			if kind == "oversize" {
				body = bytes.Repeat([]byte{'x'}, int(ftpsclient.MaxMetadata+1))
			}
			fake.read = func(string, int64) ([]byte, error) { return body, nil }
			checks := 0
			data, err := peer.ReadManifest(context.Background(), "batch.ready.json", func() error {
				checks++
				if kind == "revoked-before" || kind == "revoked-after" && checks > 1 {
					return ErrInput
				}
				return nil
			})
			if err == nil || data != nil {
				t.Fatal("unauthorized or oversized manifest escaped")
			}
			if kind == "revoked-before" {
				if fake.reads.Load() != 0 {
					t.Fatal("revoked manifest contacted source")
				}
			} else if !bytes.Equal(body, make([]byte, len(body))) {
				t.Fatal("failed metadata buffer was retained")
			}
		})
	}
}

func TestFTPSCollectionUnavailableDoesNotInventAFileAbsence(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	failure := &ftpsclient.ReplyError{Code: 550}
	fake.read = func(string, int64) ([]byte, error) { return nil, failure }
	data, err := peer.ReadManifest(context.Background(), "batch.ready.json", func() error { return nil })
	if err != failure || data != nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("FTPS unavailable/denied reply was reclassified as missing", err)
	}
}

func TestFTPSCollectionEveryStagingWriteAndCompletionRechecksCapacityAuthority(t *testing.T) {
	for _, refuseAt := range []int{0, 1, 2, 3, 4} {
		t.Run(string(rune('0'+refuseAt)), func(t *testing.T) {
			peer, fake := collectionPeerStandIn()
			digest := secure.Digest([]byte("abc"))
			fake.copy = func(name string, output io.Writer, size int64, sha string) error {
				if name != "/approved/one.csv" || size != 3 || sha != digest {
					t.Fatal("source identity changed")
				}
				for _, value := range []string{"ab", "c"} {
					if _, err := io.WriteString(output, value); err != nil {
						return err
					}
				}
				return nil
			}
			checks := 0
			var staging bytes.Buffer
			err := peer.CopyVerified(context.Background(), "one.csv", 3, digest, &staging, func() error {
				checks++
				if checks == refuseAt {
					return ErrInput
				}
				return nil
			})
			if refuseAt == 0 {
				if err != nil || staging.String() != "abc" || checks != 4 {
					t.Fatal("exact copy differs", err)
				}
			} else if !errors.Is(err, ErrInput) || checks != refuseAt {
				t.Fatal("staging/complete operation lost current guard", err)
			}
			if refuseAt == 1 && fake.copies.Load() != 0 {
				t.Fatal("revoked copy contacted source")
			}
			if refuseAt == 2 && staging.Len() != 0 {
				t.Fatal("first write escaped revoked guard")
			}
			if refuseAt == 3 && staging.String() != "ab" {
				t.Fatal("second write escaped revoked guard")
			}
		})
	}
}

func TestFTPSCollectionPayloadIntegrityFailureRemainsFailure(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	fake.copy = func(string, io.Writer, int64, string) error { return ftpsclient.ErrIntegrity }
	if err := peer.CopyVerified(context.Background(), "one.csv", 3, secure.Digest([]byte("abc")), io.Discard, func() error { return nil }); !errors.Is(err, ftpsclient.ErrIntegrity) {
		t.Fatal("payload integrity failure was accepted", err)
	}
}

func TestFTPSCollectionShorterOperationCancellationInterruptsSessionAndHidesBytes(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := []byte("untrusted private metadata")
	fake.read = func(string, int64) ([]byte, error) {
		cancel()
		select {
		case <-fake.closed:
			return body, nil
		case <-time.After(time.Second):
			t.Fatal("operation cancellation did not interrupt session")
			return nil, ErrInput
		}
	}
	data, err := peer.ReadManifest(ctx, "batch.ready.json", func() error { return nil })
	if !errors.Is(err, context.Canceled) || data != nil || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("cancelled operation exposed bytes", err)
	}
}

func TestFTPSCollectionCancellationInsideFinalGuardCannotExposeManifest(t *testing.T) {
	peer, fake := collectionPeerStandIn()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := []byte("untrusted private metadata")
	fake.read = func(string, int64) ([]byte, error) { return body, nil }
	checks := 0
	data, err := peer.ReadManifest(ctx, "batch.ready.json", func() error {
		checks++
		if checks == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || data != nil || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("final guard returned bytes after operation cancellation", err)
	}
}
