package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/ctlplne/freightctl/internal/scanner"
	"github.com/jackc/pgx/v5"
)

type ScannerReference struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Hash    string `json:"hash"`
}
type ScannerProfile struct {
	Configuration
	ValidUntil time.Time `json:"valid_until"`
}

func (t *Transaction) ScannerProfile(ctx context.Context, id string, version int, lock bool) (*ScannerProfile, error) {
	if !ValidID(id) || version < 1 {
		return nil, ErrNotFound
	}
	q := `SELECT scanner_id::text,version,definition,definition_hash,state,revision,valid_until FROM scanner_profiles WHERE scanner_id=$1 AND version=$2`
	if lock {
		q += ` FOR UPDATE`
	} else {
		q += ` FOR SHARE`
	}
	p := &ScannerProfile{}
	err := t.Tx.QueryRow(ctx, q, id, version).Scan(&p.ID, &p.Version, &p.Definition, &p.Hash, &p.State, &p.Revision, &p.ValidUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}
func (t *Transaction) ScannerProfileVersion(ctx context.Context, id string) (int, error) {
	if _, err := t.Tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Scope.Tenant+":"+t.Scope.Partner+":scanner:"+id); err != nil {
		return 0, err
	}
	var version int
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(max(version),0) FROM scanner_profiles WHERE scanner_id=$1`, id).Scan(&version)
	return version, err
}
func (t *Transaction) SaveScannerProfile(ctx context.Context, p *ScannerProfile, previous int64) error {
	event, err := t.Append(ctx, "ScannerProfileChanged", p.ID, p)
	if err != nil {
		return err
	}
	if previous == 0 {
		_, err = t.Tx.Exec(ctx, `INSERT INTO scanner_profiles VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, t.Scope.Tenant, t.Scope.Partner, t.Actor, p.ID, p.Version, p.Definition, p.Hash, p.ValidUntil, p.State, p.Revision, event)
		return err
	}
	tag, err := t.Tx.Exec(ctx, `UPDATE scanner_profiles SET state=$1,revision=$2,changed_event_id=$3 WHERE scanner_id=$4 AND version=$5 AND revision=$6`, p.State, p.Revision, event, p.ID, p.Version, previous)
	if err == nil && tag.RowsAffected() != 1 {
		return ErrRevision
	}
	return err
}
func (t *Transaction) CurrentScanner(ctx context.Context, ref ScannerReference) (*scanner.Definition, time.Time, error) {
	now, err := t.DatabaseTime(ctx)
	if err != nil {
		return nil, now, err
	}
	p, err := t.ScannerProfile(ctx, ref.ID, ref.Version, false)
	if err != nil {
		return nil, now, err
	}
	if p.State != "active" || p.Hash != ref.Hash || !now.Before(p.ValidUntil) {
		return nil, now, ErrState
	}
	var d scanner.Definition
	if json.Unmarshal(p.Definition, &d) != nil {
		return nil, now, ErrState
	}
	canonical, err := json.Marshal(d)
	if err != nil || secure.Digest(canonical) != p.Hash || !d.ValidUntil.Equal(p.ValidUntil) || scanner.Validate(d, now) != nil {
		return nil, now, ErrState
	}
	return &d, now, nil
}
func (s *Store) ScanWorkerSlot(ctx context.Context) (func() error, func(), error) {
	return s.encryptionLock(ctx, 721815039, true)
}
func releaseScannerFields(report json.RawMessage) (ScannerReference, *time.Time, error) {
	var r struct {
		Scanner *struct {
			Profile    ScannerReference `json:"profile"`
			ValidUntil time.Time        `json:"valid_until"`
		} `json:"scanner"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		return ScannerReference{}, nil, err
	}
	if r.Scanner == nil {
		return ScannerReference{}, nil, nil
	}
	return r.Scanner.Profile, &r.Scanner.ValidUntil, nil
}

// releasedScannerConfigurationCurrent extends the database's durable proof
// checks with the protected local configuration check that SQL cannot perform.
// Every new and bounded open-reader read goes through FileAvailable. A daemon
// outage does not invalidate a fresh proof: this never contacts its socket.
func (t *Transaction) releasedScannerConfigurationCurrent(ctx context.Context, id string) error {
	var ref ScannerReference
	err := t.Tx.QueryRow(ctx, `SELECT coalesce(scanner_id::text,''),coalesce(scanner_version,0),coalesce(scanner_hash,'') FROM file_releases WHERE file_id=$1`, id).Scan(&ref.ID, &ref.Version, &ref.Hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if ref.ID == "" {
		return nil
	}
	profile, _, err := t.CurrentScanner(ctx, ref)
	if err != nil {
		return err
	}
	if scanner.ConfigurationCurrent(ctx, *profile) != nil {
		return ErrState
	}
	return nil
}
