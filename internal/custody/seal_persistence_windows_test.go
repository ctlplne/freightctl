//go:build windows

package custody

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/protectedfs"
	"golang.org/x/sys/windows"
)

func TestWindowsFailedFlushCannotCreateSealCompletion(t *testing.T) {
	disk, err := Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	body := []byte("sealed without a successful original flush\n")
	f, err := protectedfs.CreateAt(disk.root, name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = protectedfs.SealReadOnly(f); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	reader, err := disk.root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err = persistCreatedSeal(reader, disk.identity, name, int64(len(body)), secure.Digest(body)); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatal("read-only flush did not fail before recording completion", err)
	}
	complete, err := checkSealPersistence(reader, disk.identity, name, int64(len(body)), secure.Digest(body))
	if err != nil || complete {
		t.Fatal("failed original flush created completion evidence", complete, err)
	}
	if state, err := disk.GeneratedSlotState(t.Context(), name); err != nil || state != "partial" {
		t.Fatal("failed original flush became an adoptable sealed slot", state, err)
	}
	if writable, err := disk.root.OpenFile(name, os.O_WRONLY, 0); err == nil {
		writable.Close()
		t.Fatal("failed flush broadened sealed data rights")
	}
	actual, err := os.ReadFile(filepath.Join(disk.root.Name(), name))
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("failed flush changed retained bytes", err)
	}
}

func TestWindowsSealCompletionRequiresActualFlushAndRejectsCopiedPhysicalIdentity(t *testing.T) {
	disk, err := Open(filepath.Join(t.TempDir(), "custody"))
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	name := Name(secure.NewID(), secure.NewID(), secure.NewID())
	body := []byte("exact native Windows reserved bytes\n")
	hash := secure.Digest(body)
	f, err := protectedfs.CreateAt(disk.root, name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(body); err != nil {
		t.Fatal(err)
	}
	// Simulate death after the access transition but before the original data
	// flush. A sealed DACL and exact digest alone must not qualify recovery.
	if err = protectedfs.SealReadOnly(f); err != nil {
		t.Fatal(err)
	}
	if state, err := disk.GeneratedSlotState(t.Context(), name); err != nil || state != "partial" {
		t.Fatal("seal without flush evidence was adopted", state, err)
	}
	if err = disk.VerifyGenerated(t.Context(), name, int64(len(body)), hash); !errors.Is(err, ErrIntegrity) {
		t.Fatal("unproved sealed object qualified", err)
	}
	if err = disk.sealObject(f, name, int64(len(body)), hash); err != nil {
		t.Fatal(err)
	}
	if err = disk.VerifyGenerated(t.Context(), name, int64(len(body)), hash); err != nil {
		t.Fatal("read-only recovery lost original successful flush evidence", err)
	}
	reader, err := disk.root.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	var recorded []byte
	var readErr error
	connection, err := reader.SyscallConn()
	if err != nil {
		reader.Close()
		t.Fatal(err)
	}
	err = connection.Control(func(fd uintptr) { recorded, readErr = querySealEA(windows.Handle(fd)) })
	reader.Close()
	if err != nil || readErr != nil || len(recorded) == 0 {
		t.Fatal("actual attached flush evidence absent", err, readErr)
	}
	if writable, err := disk.root.OpenFile(name, os.O_WRONLY, 0); err == nil {
		writable.Close()
		t.Fatal("flush evidence granted data writes")
	}
	// Retain the old physical object so its native ID cannot be recycled,then
	// copy its receipt to a different object at the same original service name.
	retained := Name(secure.NewID(), secure.NewID(), secure.NewID())
	if err = disk.root.Link(name, retained); err != nil {
		t.Fatal(err)
	}
	if err = disk.root.Remove(name); err != nil {
		t.Fatal(err)
	}
	replacement, err := protectedfs.CreateAt(disk.root, name)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if _, err = replacement.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = protectedfs.SealReadOnly(replacement); err != nil {
		t.Fatal(err)
	}
	if err = replacement.Sync(); err != nil {
		t.Fatal(err)
	}
	connection, err = replacement.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var writeErr error
	err = connection.Control(func(fd uintptr) { writeErr = setSealEA(windows.Handle(fd), recorded) })
	if err != nil || writeErr != nil {
		t.Fatal(err, writeErr)
	}
	if err = replacement.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err = disk.sync(); err != nil {
		t.Fatal(err)
	}
	if err = disk.VerifyGenerated(t.Context(), name, int64(len(body)), hash); !errors.Is(err, ErrIntegrity) {
		t.Fatal("copied native identity receipt qualified a replacement", err)
	}
	if _, err = disk.GeneratedSlotState(t.Context(), name); !errors.Is(err, ErrIntegrity) {
		t.Fatal("corrupt flush evidence was hidden by choosing another slot", err)
	}
	actual, err := os.ReadFile(filepath.Join(disk.root.Name(), name))
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("physical identity refusal modified exact retained bytes", err)
	}
}
