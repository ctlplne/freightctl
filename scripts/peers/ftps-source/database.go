package main

import (
	"context"
	"net"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/store"
	"github.com/jackc/pgx/v5"
)

func openSourceDatabase(ctx context.Context, config *configuration) (*store.Store, error) {
	if config == nil || !databasePattern.MatchString(config.Database) {
		return nil, errFixture
	}
	dsn, err := secure.ReadSecret(config.DSN, 4096)
	if err != nil {
		return nil, errFixture
	}
	defer dsn.Close()
	parsed, err := pgx.ParseConfig(string(dsn.Bytes))
	if err != nil || parsed.Database != config.Database || net.ParseIP(parsed.Host) == nil || !net.ParseIP(parsed.Host).IsLoopback() {
		return nil, errFixture
	}
	for _, fallback := range parsed.Fallbacks {
		if fallback.Host != parsed.Host || fallback.Port != parsed.Port {
			return nil, errFixture
		}
	}
	// Store.Open owns protected-reference loading and the actual runtime/RLS
	// guards. The parsed secret is a value,never a filename or command argument.
	return store.Open(ctx, config.DSN)
}
