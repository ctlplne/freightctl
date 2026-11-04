//go:build integration

package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/custody"
	"github.com/ctlplne/freightctl/internal/store"
)

func waitFTPSCollectionSQL(t *testing.T, f *fixture, limit time.Duration, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.ctx, limit)
	defer cancel()
	for {
		var ready bool
		if err := f.admin.QueryRow(ctx, query, args...).Scan(&ready); err != nil {
			t.Fatal("FTPS collection recovery observation failed", err)
		}
		if ready {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("FTPS collection recovery observation timed out")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// This uses the ordinary public CLI in an exact owned child process. The TLS
// source is the native freightctl stand-in, not an independent stock peer.
// Keep the original eight-second SQL barrier and real thirty-second lease;
// neither a backdated lease nor a simulated cancellation proves process death.
func TestFTPSCollectionKilledAfterSealRecoversOriginalObjectWithoutSourceContact(t *testing.T) {
	binary := routingKeyCLI(t)
	for _, implicit := range []bool{false, true} {
		t.Run(fmt.Sprint(implicit), func(t *testing.T) {
			x := newFTPSCollection(t, implicit, false, false)
			f := x.f
			body := bytes.Repeat([]byte("account,amount\n0004,123.00\n"), 16)
			publishFTPSCollectionObject(t, x, "sealed.csv", body)
			manifest := publishFTPSCollectionManifest(t, x, x.source.Manifest, []CollectionFile{{Name: "sealed.csv", Size: int64(len(body)), SHA256: secure.Digest(body)}})
			job, _ := startCollection(t, f, x.selection, "ftps-process-crash-start")
			request, err := json.Marshal(CollectionWorkRequest{Hash: job.Hash})
			if err != nil {
				t.Fatal(err)
			}
			requestPath := filepath.Join(t.TempDir(), "collection-work.json")
			if err = os.WriteFile(requestPath, request, 0600); err != nil {
				t.Fatal(err)
			}
			argv := []string{"workflow-collection-work", "--dsn-file", f.runtimePath,
				"--token-file", f.tokenPath, "--tenant", f.scope.Tenant, "--partner", f.scope.Partner,
				"--storage", f.storagePath, "--collection-id", job.ID, "--request-file", requestPath,
				"--idempotency-key", "ftps-killed-collection-worker"}
			command := func() *exec.Cmd {
				cmd := exec.CommandContext(f.ctx, binary, argv...)
				cmd.Env = append(os.Environ(), "GOMAXPROCS=1", "GOMEMLIMIT=192MiB")
				return cmd
			}
			// The barrier is scoped to this disposable database and exact payload.
			barrier := `CREATE FUNCTION freightctl_ftps_collection_seal_pause() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.sha256='` + secure.Digest(body) + `' THEN PERFORM pg_sleep(8);END IF;RETURN NEW;END $$;CREATE TRIGGER freightctl_ftps_collection_seal_pause BEFORE INSERT ON files FOR EACH ROW EXECUTE FUNCTION freightctl_ftps_collection_seal_pause()`
			if _, err = f.admin.Exec(f.ctx, barrier); err != nil {
				t.Fatal(err)
			}
			drop := `DROP TRIGGER IF EXISTS freightctl_ftps_collection_seal_pause ON files;DROP FUNCTION IF EXISTS freightctl_ftps_collection_seal_pause()`
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if _, err := f.admin.Exec(ctx, drop); err != nil {
					t.Error("exact FTPS acceptance barrier cleanup", err)
				}
			})
			child := command()
			var stdout, stderr bytes.Buffer
			child.Stdout, child.Stderr = &stdout, &stderr
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					_ = child.Process.Kill()
					_ = child.Wait()
				}
			})
			waitFTPSCollectionSQL(t, f, 12*time.Second, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep')`)
			staged, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
			if err != nil || staged.Job.State != "reading" || staged.Job.Captured || staged.Job.Attempts != 1 || staged.Job.Fence != 1 || staged.Job.Until == nil || len(staged.Inputs) != 1 {
				t.Fatal("process did not reach original live pre-acceptance boundary", err)
			}
			input := staged.Inputs[0]
			if input.State != "pending" || input.FileID != nil || input.Fence != 1 || input.Owner != staged.Job.Owner {
				t.Fatal("pre-acceptance input already acquired custody or lost its original fence")
			}
			sealed, err := f.s.Custody.Disk.VerifiedContext(f.ctx, custody.Name(f.scope.Tenant, f.scope.Partner, input.ObjectID), input.Size, input.SHA256)
			if err != nil {
				t.Fatal("original child did not durably seal exact source bytes", err)
			}
			stat, statErr := sealed.Stat()
			got, readErr := io.ReadAll(io.LimitReader(sealed, int64(len(body))+1))
			sealed.Close()
			if statErr != nil || readErr != nil || stat.Mode().Perm() != 0400 || !bytes.Equal(got, body) {
				t.Fatal("pre-acceptance sealed object identity or private mode differs")
			}
			if _, err = f.s.Custody.StatPath(f.ctx, f.scope, input.Target); !errors.Is(err, store.ErrNotFound) {
				t.Fatal("pre-acceptance source bytes became public", err)
			}
			if err = child.Process.Kill(); err != nil {
				t.Fatal("could not kill the exact original collection child", err)
			}
			err = child.Wait()
			waited = true
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("original collection child was not killed", err)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL || stdout.Len() != 0 {
				t.Fatal("original worker returned a receipt or did not die by SIGKILL")
			}
			if _, err = f.admin.Exec(f.ctx, drop); err != nil {
				t.Fatal(err)
			}
			retained, err := f.s.CollectionStatus(f.ctx, f.scope, job.ID)
			if err != nil || retained.Job.State != "reading" || retained.Job.Attempts != 1 || retained.Job.Fence != 1 || !reflect.DeepEqual(retained.Inputs, staged.Inputs) || retained.Job.Until == nil || retained.Job.Until.Before(*staged.Job.Until) || retained.Job.Owner != staged.Job.Owner {
				t.Fatal("worker death shortened its lease or changed unaccepted input", err)
			}
			contacts := x.listener.contacts.Load()
			if contacts < 1 {
				t.Fatal("original worker never contacted the real native FTPS source")
			}
			// Remove both source names using the producer's exact namespace CAS.
			// Recovery must use the frozen manifest and sealed object, not reread.
			for _, name := range []string{"sealed.csv", x.source.Manifest} {
				p := path.Join("/inbox", name)
				entry, err := x.producer.s.Custody.StatPath(x.producer.ctx, x.producer.scope, p)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = x.producer.s.Custody.PathCommand(x.producer.ctx, x.producer.scope, secure.NewID(), store.PathCommand{Operation: "remove", Path: p, ExpectedRevision: &entry.Revision}); err != nil {
					t.Fatal("producer exact-revision removal", err)
				}
			}
			blocked := command()
			var blockedOut, blockedErr bytes.Buffer
			blocked.Stdout, blocked.Stderr = &blockedOut, &blockedErr
			if err = blocked.Run(); !errors.As(err, &exit) || exit.ExitCode() != 1 || blockedOut.Len() != 0 || blockedErr.String() != "freightctl: "+store.ErrCollection.Error()+"\n" || x.listener.contacts.Load() != contacts {
				t.Fatal("replacement bypassed the live original lease or contacted source", err)
			}
			waitFTPSCollectionSQL(t, f, 35*time.Second, `SELECT clock_timestamp()>=lease_until FROM workflow_collection_jobs WHERE id=$1`, job.ID)
			run := func() Result {
				t.Helper()
				cmd := command()
				var out, diagnostic bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &diagnostic
				if err := cmd.Run(); err != nil || diagnostic.Len() != 0 {
					t.Fatalf("public recovery command failed: %v (diagnostic sha256 %s)", err, secure.Digest(diagnostic.Bytes()))
				}
				var result Result
				if json.Unmarshal(out.Bytes(), &result) != nil {
					t.Fatal("public recovery did not return its typed receipt")
				}
				return result
			}
			first, replay := run(), run()
			var action, replayed CollectionAction
			if first.Replayed || !replay.Replayed || json.Unmarshal(first.Resource, &action) != nil || json.Unmarshal(replay.Resource, &replayed) != nil || !reflect.DeepEqual(action, replayed) || action.ID != job.ID || action.Hash != job.Hash || action.State != "captured" {
				t.Fatal("original stopped key did not recover one exact captured receipt")
			}
			recovered := requireCollectedFTPSBytes(t, x, job.ID, body)
			_, manifestHash, _ := digest(manifest)
			if recovered.Job.Attempts != 2 || recovered.Job.Fence != 2 || recovered.Job.ManifestHash == nil || *recovered.Job.ManifestHash != manifestHash || recovered.Inputs[0].ObjectID != input.ObjectID || recovered.Inputs[0].ID != input.ID || recovered.Inputs[0].FileID == nil || *recovered.Inputs[0].FileID != input.ObjectID || x.listener.contacts.Load() != contacts {
				t.Fatal("takeover repeated source contact or replaced the sealed custody revision")
			}
			var files, events int
			if err = f.admin.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM files WHERE file_id=$1),(SELECT count(*) FROM events WHERE resource_id=$1 AND kind='FileAccepted')`, input.ObjectID).Scan(&files, &events); err != nil || files != 1 || events != 1 {
				t.Fatal("process recovery duplicated or lost durable acceptance", files, events, err)
			}
		})
	}
}
