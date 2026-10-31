//go:build integration

package workflow

import (
	"context"
	"testing"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
)

func TestNamespaceAcceptanceAndCollectionCompletionAllowCredentialMutation(t *testing.T) {
	f, _, x := collectionFixture(t)
	_, account := approvalPeer(t, f, "Credential updated during namespace publication", []string{"inspect"})
	job, owner, inputs := sealedCollectionFixture(t, f, x, "namespace-order", "abc")
	if err := f.s.acceptCollectionInput(f.ctx, f.scope, job.ID, owner, job.Fence, &inputs[0]); err != nil {
		t.Fatal(err)
	}
	namespace, err := f.s.Custody.DB.Begin(f.ctx, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	defer namespace.Tx.Rollback(context.Background())
	if err = namespace.NamespaceLock(f.ctx); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 1)
	go func() {
		_, e := f.s.completeCollectionWork(f.ctx, f.scope, job.ID, owner, job.Fence, "namespace-complete", secure.Digest([]byte("namespace-complete")))
		completed <- e
	}()
	writer := make(chan error, 1)
	completionDone, writerStarted, writerDone := false, false, false
	defer func() {
		namespace.Tx.Rollback(context.Background())
		if !completionDone {
			select {
			case <-completed:
			case <-time.After(5 * time.Second):
				t.Error("completion did not leave namespace wait")
			}
		}
		if writerStarted && !writerDone {
			select {
			case <-writer:
			case <-time.After(5 * time.Second):
				t.Error("credential writer remained blocked")
			}
		}
	}()
	wait := func(query string) bool {
		t.Helper()
		var found bool
		if e := f.admin.QueryRow(f.ctx, query).Scan(&found); e != nil {
			t.Fatal(e)
		}
		return found
	}
	until := time.Now().Add(5 * time.Second)
	for !wait(`SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='freightctl' AND l.locktype='advisory' AND NOT l.granted AND a.query LIKE 'SELECT pg_advisory_xact_lock(%')`) {
		if time.Now().After(until) {
			t.Fatal("completion did not reach actual namespace wait")
		}
		time.Sleep(10 * time.Millisecond)
	}
	writerStarted = true
	go func() {
		_, e := f.s.Custody.DB.ChangeAccount(f.ctx, f.scope, "rotate-under-namespace-wait", store.AccountCommand{Operation: "rotate", ID: account.ID, ExpectedRevision: 1, CredentialHash: secure.Digest([]byte(secure.NewID()))})
		writer <- e
	}()
	until = time.Now().Add(5 * time.Second)
	for {
		select {
		case err = <-writer:
			writerDone = true
		default:
		}
		if writerDone {
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		if wait(`SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a USING(pid) WHERE a.datname=current_database() AND a.application_name='freightctl' AND l.locktype='advisory' AND NOT l.granted AND a.query LIKE 'INSERT INTO account_revisions%')`) {
			break
		}
		if time.Now().After(until) {
			t.Fatal("credential writer neither completed nor reached its actual effect guard")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A namespace owner accepting a sealed input needs this same shared guard.
	// A completion queued behind it must not hold the guard needed by a writer
	// ahead of that acceptance in the advisory-lock queue.
	ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
	err = namespace.ScheduleLock(ctx, false)
	cancel()
	if err != nil {
		t.Fatal("namespace/calendar cycle prevents ordinary acceptance", err)
	}
	namespace.Tx.Rollback(f.ctx)
	select {
	case err = <-completed:
		completionDone = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("completion did not finish after namespace release")
	}
	if !writerDone {
		select {
		case err = <-writer:
			writerDone = true
			if err != nil {
				t.Fatal("credential mutation failed in namespace/calendar cycle", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("credential writer did not finish")
		}
	}
}
