package store

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// ApprovalPolicyBinding is an immutable revision and its administrator-set rule.
// The policy's resource type supplies its scope; the binding grants no authority.
type ApprovalPolicyBinding struct {
	Revision int64  `json:"revision"`
	Mode     string `json:"mode"`
}

// BeginApproval orders account authority before policy/review locks. It grants
// no manager, payload or private-record access; callers still require roles.
func (s *Store) BeginApproval(ctx context.Context, scope Scope) (*Transaction, error) {
	return s.beginAuthenticated(ctx, scope, pgx.TxOptions{}, true)
}
