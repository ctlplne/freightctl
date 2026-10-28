package store

import (
	"bytes"
	"context"
	"errors"
	"strings"

	secure "github.com/ctlplne/freightctl/internal/crypto"
	"github.com/jackc/pgx/v5"
)

type SSHKey struct {
	ID          string `json:"key_id"`
	Actor       string `json:"actor_id"`
	Fingerprint string `json:"fingerprint"`
	EventID     string `json:"changed_event_id"`
	Revoked     bool   `json:"revoked"`
}

// ManageSSHKey is a local administrative operation, requiring both the
// protected administrator DSN and the target identity's protected token.
// Revoked keys are never resurrected by enrollment retries.
func ManageSSHKey(ctx context.Context, adminPath, tokenPath, tenant, partner string, public secure.SSHPublic, revokeID string) (*SSHKey, error) {
	if !ValidID(tenant) || !ValidID(partner) {
		return nil, ErrUnauthorized
	}
	if revokeID != "" && !ValidID(revokeID) {
		return nil, ErrNotFound
	}
	var err error
	if revokeID == "" {
		public, err = secure.ValidateSSHPublic(public)
		if err != nil {
			return nil, err
		}
	}
	secret, err := secure.ReadSecret(tokenPath, 64)
	if err != nil {
		return nil, err
	}
	if len(secret.Bytes) != 64 {
		secret.Close()
		return nil, ErrUnauthorized
	}
	scope := Scope{Tenant: tenant, Partner: partner, TokenHash: secure.Digest(secret.Bytes)}
	secret.Close()
	pool, err := connect(ctx, adminPath)
	if err != nil {
		return nil, err
	}
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.tenant_id',$1,true),set_config('freightctl.partner_id',$2,true)`, tenant, partner); err != nil {
		return nil, err
	}
	t := &Transaction{Tx: tx, Scope: scope}
	if err = t.authenticate(ctx); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('freightctl.actor_id',$1,true)`, t.Actor); err != nil {
		return nil, err
	}
	result := &SSHKey{}
	var wire []byte
	if revokeID == "" {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tenant+":"+partner+":ssh:"+public.Fingerprint); err != nil {
			return nil, err
		}
		err = tx.QueryRow(ctx, `SELECT key_id::text,actor_id::text,fingerprint,public_wire,changed_event_id::text,revoked_at IS NOT NULL FROM ssh_keys WHERE tenant_id=$1 AND partner_id=$2 AND fingerprint=$3 FOR UPDATE`, tenant, partner, public.Fingerprint).Scan(&result.ID, &result.Actor, &result.Fingerprint, &wire, &result.EventID, &result.Revoked)
		if err == nil {
			if result.Actor != t.Actor || !bytes.Equal(wire, public.Wire) || result.Revoked {
				return nil, ErrState
			}
			return result, tx.Commit(ctx)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		result.ID = secure.NewID()
		result.Actor = t.Actor
		result.Fingerprint = public.Fingerprint
		result.EventID, err = t.Append(ctx, "SSHKeyEnrolled", result.ID, map[string]string{"actor_id": t.Actor, "fingerprint": public.Fingerprint, "public_sha256": secure.Digest(public.Wire)})
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ssh_keys(tenant_id,partner_id,key_id,actor_id,fingerprint,public_wire,changed_event_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, partner, result.ID, t.Actor, public.Fingerprint, public.Wire, result.EventID)
	} else {
		err = tx.QueryRow(ctx, `SELECT key_id::text,actor_id::text,fingerprint,public_wire,changed_event_id::text,revoked_at IS NOT NULL FROM ssh_keys WHERE tenant_id=$1 AND partner_id=$2 AND key_id=$3 AND actor_id=$4 FOR UPDATE`, tenant, partner, revokeID, t.Actor).Scan(&result.ID, &result.Actor, &result.Fingerprint, &wire, &result.EventID, &result.Revoked)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if result.Revoked {
			return result, tx.Commit(ctx)
		}
		result.EventID, err = t.Append(ctx, "SSHKeyRevoked", result.ID, map[string]string{"actor_id": t.Actor, "fingerprint": result.Fingerprint, "public_sha256": secure.Digest(wire)})
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `UPDATE ssh_keys SET revoked_at=clock_timestamp(),changed_event_id=$1 WHERE tenant_id=$2 AND partner_id=$3 AND key_id=$4`, result.EventID, tenant, partner, result.ID)
		result.Revoked = true
	}
	if err != nil {
		return nil, err
	}
	if err = t.Reauthorize(ctx); err != nil {
		return nil, err
	}
	return result, tx.Commit(ctx)
}

// AllowSSHKey selects an active registered public key. Possession is verified
// by internal/crypto's SSH handshake before a protocol session can use it.
func (s *Store) AllowSSHKey(ctx context.Context, username string, public secure.SSHPublic) (secure.SSHPrincipal, error) {
	parts := strings.Split(username, ".")
	if len(parts) != 3 || !ValidID(parts[0]) || !ValidID(parts[1]) || !ValidID(parts[2]) {
		return secure.SSHPrincipal{}, ErrUnauthorized
	}
	validated, err := secure.ValidateSSHPublic(public)
	if err != nil {
		return secure.SSHPrincipal{}, ErrUnauthorized
	}
	scope := Scope{Tenant: parts[0], Partner: parts[1], Actor: parts[2], SSHKeyFingerprint: validated.Fingerprint}
	t, err := s.Begin(ctx, scope)
	if err != nil {
		return secure.SSHPrincipal{}, err
	}
	defer t.Tx.Rollback(ctx)
	var exact bool
	err = t.Tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ssh_keys WHERE actor_id=$1 AND fingerprint=$2 AND public_wire=$3 AND revoked_at IS NULL)`, t.Actor, validated.Fingerprint, validated.Wire).Scan(&exact)
	if err != nil {
		return secure.SSHPrincipal{}, err
	}
	if !exact {
		return secure.SSHPrincipal{}, ErrUnauthorized
	}
	principal := secure.SSHPrincipal{Tenant: scope.Tenant, Partner: scope.Partner, Actor: t.Actor, Fingerprint: validated.Fingerprint, AuthorityRevision: t.AuthorityRevision}
	if err = t.Reauthorize(ctx); err != nil {
		return secure.SSHPrincipal{}, err
	}
	if err = t.Tx.Commit(ctx); err != nil {
		return secure.SSHPrincipal{}, err
	}
	return principal, nil
}
