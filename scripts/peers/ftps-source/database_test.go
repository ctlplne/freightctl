package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourceDatabaseUsesTheProtectedReferenceContractWithoutOpeningANetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.dsn")
	database := "freightctl_ftps_" + strings.Repeat("b", 32)
	raw := "postgresql://runtime:PRIVATE_DATABASE_CANARY@127.0.0.1:25432/" + database + "?sslmode=disable"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	// The real store API must read a protected file,parse it and reach its
	// canceled-context boundary. No PostgreSQL or network connection can start.
	_, err := openSourceDatabase(ctx, &configuration{Database: database, DSN: path})
	if err == nil || err.Error() != "database unavailable" {
		t.Fatalf("source did not reach the real store reference boundary;missing_path=%t;private_message=%t", errors.Is(err, os.ErrNotExist), err != nil && strings.Contains(err.Error(), "PRIVATE_DATABASE_CANARY"))
	}
}

func TestSourceDatabaseRefusesWrongEstateNonloopbackAndFallbackBeforeStoreOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.dsn")
	database := "freightctl_ftps_" + strings.Repeat("b", 32)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, raw := range []string{
		"postgresql://runtime:PRIVATE_DATABASE_CANARY@127.0.0.1:25432/other?sslmode=disable",
		"postgresql://runtime:PRIVATE_DATABASE_CANARY@outside.invalid:25432/" + database,
		"postgresql://runtime:PRIVATE_DATABASE_CANARY@127.0.0.1:25432/" + database + "?host=127.0.0.1,127.0.0.2&sslmode=disable",
		"not a connection string",
	} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := openSourceDatabase(ctx, &configuration{Database: database, DSN: path}); !errors.Is(err, errFixture) {
			t.Fatal("source database scope failure reached store open")
		}
	}
	if string(sourceFailureDiagnostic(sourceDatabaseFailure)) != "{\"kind\":\"freightctl-ftps-source-failure-v1\",\"stage\":\"database\"}\n" {
		t.Fatal("database failure did not retain its fixed private-safe category")
	}
}
