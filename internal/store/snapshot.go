package store

import (
	"context"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type AuditSnapshot struct {
	Format     string    `json:"format"`
	ID         string    `json:"id"`
	Tenant     string    `json:"tenant_id"`
	Partner    string    `json:"partner_id"`
	At         time.Time `json:"snapshot_at"`
	EventCount int       `json:"event_count"`
	Events     []Event   `json:"events"`
	Boundary   string    `json:"protection_boundary"`
}

// SnapshotEvents uses one MVCC view: rows do not drift while the export is read.
// A separate current-authority transaction is required before disclosure.
func (s *Store) SnapshotEvents(ctx context.Context, scope Scope, maxEvents, maxBytes int) (*AuditSnapshot, error) {
	if maxEvents < 1 || maxEvents > 100000 || maxBytes < 1024 || maxBytes > secure.MaxAuditPayload {
		return nil, ErrLimit
	}
	t, err := s.begin(ctx, scope, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer t.Tx.Rollback(ctx)
	snapshot := &AuditSnapshot{Format: secure.AuditFormat, ID: secure.NewID(), Tenant: scope.Tenant, Partner: scope.Partner, Events: make([]Event, 0), Boundary: "Signature detects changes after export. It does not prove the database was unmodified before this snapshot or that the receiver consumed it."}
	if err = t.Tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&snapshot.At); err != nil {
		return nil, err
	}
	rows, err := t.Tx.Query(ctx, `SELECT event_id::text,actor_id::text,kind,resource_id::text,payload,happened_at FROM events ORDER BY happened_at,event_id LIMIT $1`, maxEvents+1)
	if err != nil {
		return nil, err
	}
	budget := 1024
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.ActorID, &e.Kind, &e.ResourceID, &e.Payload, &e.At); err != nil {
			rows.Close()
			return nil, err
		}
		budget += len(e.Payload) + len(e.Kind) + 512
		if len(snapshot.Events) >= maxEvents || budget > maxBytes {
			rows.Close()
			return nil, ErrLimit
		}
		snapshot.Events = append(snapshot.Events, e)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	snapshot.EventCount = len(snapshot.Events)
	if err = t.Tx.Commit(ctx); err != nil {
		return nil, err
	}
	return snapshot, nil
}
