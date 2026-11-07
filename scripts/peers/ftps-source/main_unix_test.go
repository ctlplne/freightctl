//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestSourceWitnessedListenerClosePreservesActualAcceptedCount(t *testing.T) {
	for _, queued := range []bool{false, true} {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		w := &witness{path: filepath.Join(t.TempDir(), "counter.json"), value: snapshot{Schema: 1, Kind: "freightctl-ftps-source-witness-v1", Mode: "explicit", Port: listener.Addr().(*net.TCPAddr).Port}}
		if err = w.save(); err != nil {
			listener.Close()
			t.Fatal(err)
		}
		observed := &witnessedListener{TCPListener: listener, witness: w}
		defer observed.Close()
		if queued {
			peer, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
		}
		if err = observed.Close(); err != nil {
			t.Fatalf("actual source close failed;queued=%t;failure=%v", queued, err)
		}
		if err = observed.Close(); err != nil {
			t.Fatal("same source close not idempotent")
		}
		want := 0
		if queued {
			want = 1
		}
		if w.value.Accepted != want || w.value.Exhausted {
			t.Fatal("actual source shutdown lost a queued accepted connection")
		}
	}
}

func TestSourceWitnessIsPrivateBoundedAndDoesNotResetAfterExhaustion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counter.json")
	w := witness{path: path, value: snapshot{Schema: 1, Kind: "freightctl-ftps-source-witness-v1", Mode: "explicit", Port: 49151}}
	if err := w.save(); err != nil {
		t.Fatal(err)
	}
	for count := 1; count <= 16; count++ {
		if err := w.accepted(); err != nil {
			t.Fatal("exact counter lost an admitted accept", count, err)
		}
	}
	for count := 0; count < 3; count++ {
		if !errors.Is(w.accepted(), errFixture) {
			t.Fatal("over-budget accept became admissible")
		}
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("witness output must remain owner-only", err)
	}
	var got snapshot
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &got) != nil || got.Accepted != 17 || !got.Exhausted || got.Stopped {
		t.Fatal("counter overflow was hidden or rebound", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "counter.json" {
		t.Fatal("atomic witness writes leaked temporary files", err)
	}
}

func configurationFixture(t *testing.T) (string, string, configuration) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	estate := filepath.Join(root, ".private", "ftps-"+strings.Repeat("a", 32))
	directory := filepath.Join(estate, "source-helper-explicit")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	c := configuration{Database: "freightctl_ftps_" + strings.Repeat("b", 32), DSN: filepath.Join(estate, "pg-runtime.dsn"), Storage: filepath.Join(estate, "custody"), Certificate: filepath.Join(estate, "cert.pem"), Key: filepath.Join(estate, "key.pem"), Mode: "explicit"}
	return root, filepath.Join(directory, "config.json"), c
}

func TestSourceConfigurationBindsOnlyFreshPrivateEstateAndReferences(t *testing.T) {
	root, path, c := configurationFixture(t)
	write := func(c configuration) {
		t.Helper()
		raw, err := json.Marshal(c)
		if err != nil || os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("cannot write exact fixture configuration", err)
		}
	}
	write(c)
	got, directory, err := readConfiguration(root, path)
	if err != nil || *got != c || directory != filepath.Dir(path) {
		t.Fatal("exact source fixture was rejected", err)
	}
	for _, change := range []func(*configuration){
		func(c *configuration) { c.Database = "freightctl" },
		func(c *configuration) { c.DSN = "/private/retained.dsn" },
		func(c *configuration) { c.Storage = filepath.Dir(c.Storage) },
		func(c *configuration) { c.Key = "/private/other.key" },
		func(c *configuration) { c.Mode = "implicit" },
	} {
		altered := c
		change(&altered)
		write(altered)
		if _, _, err := readConfiguration(root, path); !errors.Is(err, errFixture) {
			t.Fatal("source fixture escaped its exact estate", err)
		}
	}
	write(c)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readConfiguration(root, path); !errors.Is(err, errFixture) {
		t.Fatal("public source configuration was accepted", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".original"); err != nil || os.Symlink(path+".original", path) != nil {
		t.Fatal("cannot prepare source symlink refusal", err)
	}
	if _, _, err := readConfiguration(root, path); !errors.Is(err, errFixture) {
		t.Fatal("linked source configuration was accepted", err)
	}
}

func TestSourceFixtureRefusesOutsideGitHubBeforeAnyConfigurationOrSocket(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "false")
	if !errors.Is(run(), errFixture) {
		t.Fatal("source fixture ran outside its disposable GitHub environment")
	}
}

func TestSourceConfigurationCannotAcquireMeaningThroughDuplicateOrUntypedFields(t *testing.T) {
	valid := `{"database":"fresh","dsn_file":"dsn","storage":"disk","certificate":"cert","key":"key","mode":"explicit"}`
	if _, err := decodeConfiguration([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"database":"fresh"`, `"database":"old","database":"fresh"`, 1),
		strings.Replace(valid, `"database":"fresh"`, `"database":null`, 1),
		strings.Replace(valid, `"mode":"explicit"`, `"mode":true`, 1),
		strings.Replace(valid, `"key":"key"`, `"key":{}`, 1),
		strings.Replace(valid, `"mode":"explicit"`, `"MODE":"explicit"`, 1),
		strings.Replace(valid, `"mode":"explicit"`, `"mode":"explicit","authority":"invented"`, 1),
		strings.Replace(valid, `,"mode":"explicit"`, ``, 1),
		valid + `{}`,
		`[]`,
	} {
		if _, err := decodeConfiguration([]byte(raw)); !errors.Is(err, errFixture) {
			t.Fatal("ambiguous source configuration was accepted", err)
		}
	}
}

func TestPendingSourceAcceptDrainClosesOnlyAcceptedHandlesWithinItsFixedBudget(t *testing.T) {
	var closed []int
	count, records := 0, 0
	err := drainAccepted(func() (int, error) {
		count++
		if count > 3 {
			return -1, syscall.EAGAIN
		}
		return count + 10, nil
	}, func(fd int) error { closed = append(closed, fd); return nil }, func() error { records++; return nil })
	if err != nil || !reflect.DeepEqual(closed, []int{11, 12, 13}) || records != 3 || count != 4 {
		t.Fatal("pending source accepts were lost, duplicated or not closed", err)
	}
	count = 0
	err = drainAccepted(func() (int, error) { count++; return count + 20, nil }, func(int) error { return nil }, func() error { return nil })
	if !errors.Is(err, errFixture) || count != 17 {
		t.Fatal("source drain became unbounded", err)
	}
	for _, accepted := range []func() (int, error){
		func() (int, error) { return -1, nil },
		func() (int, error) { return -1, syscall.EACCES },
	} {
		if !errors.Is(drainAccepted(accepted, func(int) error { t.Fatal("closed a handle never accepted"); return nil }, func() error { return nil }), errFixture) {
			t.Fatal("unproven source drain was treated as zero contacts")
		}
	}
}
