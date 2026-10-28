//go:build integration

package custody_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestRevisionWriterCloseGapsAndDisconnect(t *testing.T) {
	f := setup(t)
	w, err := f.service.OpenRevisionWriter(f.ctx, f.a, "/file", custody.WriteOptions{Create: true, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.WriteAt([]byte("world"), 5); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/file"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("unclosed revision was published", err)
	}
	if _, err = w.WriteAt([]byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := f.service.StatPath(f.ctx, f.a, "/file")
	if err != nil {
		t.Fatal(err)
	}
	_, reader, err := f.service.DownloadPath(f.ctx, f.a, "/file")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(data, []byte("helloworld")) {
		t.Fatal("incorrect out-of-order stream", err)
	}
	interrupted, err := f.service.OpenRevisionWriter(f.ctx, f.a, "/file", custody.WriteOptions{Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = interrupted.WriteAt([]byte("complete but unclosed"), 0); err != nil {
		t.Fatal(err)
	}
	interrupted.TransferError(io.ErrUnexpectedEOF)
	if err = interrupted.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("disconnect cleanup published a revision", err)
	}
	current, err := f.service.StatPath(f.ctx, f.a, "/file")
	if err != nil || current.FileID != original.FileID || current.Revision != original.Revision {
		t.Fatal("interrupted replacement changed publication", err)
	}
	gap, err := f.service.OpenRevisionWriter(f.ctx, f.a, "/gap", custody.WriteOptions{Create: true, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = gap.WriteAt([]byte("tail"), 16); err != nil {
		t.Fatal(err)
	}
	if err = gap.Close(); !errors.Is(err, custody.ErrIntegrity) {
		t.Fatal("missing packets became zero-filled published bytes", err)
	}
	if _, err = f.service.StatPath(f.ctx, f.a, "/gap"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	files, err := os.ReadDir(f.root)
	if err != nil || len(files) != 1 {
		t.Fatal("ordinary failures left unsealed staging", len(files), err)
	}
}
func TestSSHKeyLifecycleRevokesOpenReadersAndWriters(t *testing.T) {
	f := setup(t)
	token := filepath.Join(t.TempDir(), "token")
	if err := secure.WriteToken(token); err != nil {
		t.Fatal(err)
	}
	if err := store.Provision(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), f.a.Tenant, f.a.Partner, token); err != nil {
		t.Fatal(err)
	}
	secret, err := secure.ReadSecret(token, 64)
	if err != nil {
		t.Fatal(err)
	}
	scope := store.Scope{Tenant: f.a.Tenant, Partner: f.a.Partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	identity, err := f.db.Identity(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	enroll := func() (*store.SSHKey, secure.SSHPublic, store.Scope) {
		t.Helper()
		dir := t.TempDir()
		private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
		if err := secure.GenerateSSHHostIdentity(private, public); err != nil {
			t.Fatal(err)
		}
		pub, err := secure.ReadSSHPublic(public)
		if err != nil {
			t.Fatal(err)
		}
		key, err := store.ManageSSHKey(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), token, scope.Tenant, scope.Partner, pub, "")
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := store.ManageSSHKey(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), token, scope.Tenant, scope.Partner, pub, "")
		if err != nil || repeated.ID != key.ID || repeated.EventID != key.EventID {
			t.Fatal("enrollment repeat", err)
		}
		principal, err := f.db.AllowSSHKey(f.ctx, identity.SSHUsername, pub)
		if err != nil {
			t.Fatal(err)
		}
		return key, pub, store.Scope{Tenant: principal.Tenant, Partner: principal.Partner, Actor: principal.Actor, SSHKeyFingerprint: principal.Fingerprint, AuthorityRevision: principal.AuthorityRevision}
	}
	revoke := func(key *store.SSHKey) {
		t.Helper()
		result, err := store.ManageSSHKey(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), token, scope.Tenant, scope.Partner, secure.SSHPublic{}, key.ID)
		if err != nil || !result.Revoked {
			t.Fatal(err)
		}
	}
	key, pub, sshScope := enroll()
	w, err := f.service.OpenRevisionWriter(f.ctx, sshScope, "/ssh", custody.WriteOptions{Create: true, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.WriteAt([]byte("registered key bytes"), 0); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := f.service.OpenRevisionReader(f.ctx, sshScope, "/ssh")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = r.ReadAt(make([]byte, 3), 0); err != nil {
		t.Fatal(err)
	}
	revoke(key)
	if _, err = r.ReadAt(make([]byte, 3), 3); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("open reader ignored key revocation", err)
	}
	if _, err = f.db.AllowSSHKey(f.ctx, identity.SSHUsername, pub); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("revoked key authenticated", err)
	}
	if _, err = store.ManageSSHKey(f.ctx, os.Getenv("FREIGHTCTL_TEST_ADMIN_FILE"), token, scope.Tenant, scope.Partner, pub, ""); !errors.Is(err, store.ErrState) {
		t.Fatal("revoked key resurrected", err)
	}
	key, _, sshScope = enroll()
	w, err = f.service.OpenRevisionWriter(f.ctx, sshScope, "/revoked", custody.WriteOptions{Create: true, Truncate: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.WriteAt([]byte("must not publish"), 0); err != nil {
		t.Fatal(err)
	}
	revoke(key)
	if err = w.Close(); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatal("writer published after revocation", err)
	}
	if _, err = f.service.StatPath(f.ctx, scope, "/revoked"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("revoked writer left a publication", err)
	}
	if _, err = f.db.Identity(f.ctx, scope); err != nil {
		t.Fatal("key revocation revoked the unrelated token", err)
	}
}
