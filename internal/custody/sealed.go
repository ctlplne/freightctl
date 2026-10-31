package custody

import (
	"context"

	"github.com/ctlplne/freightctl/internal/store"
	"github.com/ctlplne/freightctl/internal/vpath"
)

type sealedAcceptance struct {
	id   string
	bind func(context.Context, *store.Transaction, *store.File, bool) error
}

// AcceptSealedAt accepts an already synced immutable object under ordinary path,
// capacity and intake policy, with namespace publication deferred to the
// completed collection batch or ordinary intake release. Its binder records the source
// intent in the SAME SQL transaction as file acceptance and its retry receipt.
// No transport can supply this callback. Verify before taking control-state
// locks; a long remote read never holds a PostgreSQL metadata transaction open.
func (s *Service) AcceptSealedAt(ctx context.Context, scope store.Scope, key string, file store.File, target UploadTarget, bind func(context.Context, *store.Transaction, *store.File, bool) error) (*store.File, bool, error) {
	canonical, e := vpath.Canonical(target.Path)
	if e != nil || canonical == "/" || canonical != target.Path || vpath.ControlPath(canonical) || !store.ValidID(file.ID) || file.Size < 0 || file.Size > s.MaxFile || !digestPattern.MatchString(file.SHA256) || bind == nil || s.Disk == nil {
		return nil, false, ErrInput
	}
	if target.Modified != nil {
		return nil, false, ErrInput
	}
	data, e := s.Disk.VerifiedContext(ctx, Name(scope.Tenant, scope.Partner, file.ID), file.Size, file.SHA256)
	if e != nil {
		return nil, false, e
	}
	st, e := data.Stat()
	if e != nil || st.Mode().Perm() != 0400 {
		data.Close()
		return nil, false, ErrIntegrity
	}
	if e = data.Close(); e != nil {
		return nil, false, e
	}
	return s.accept(ctx, scope, key, file.Size, file.SHA256, nil, &target, &sealedAcceptance{id: file.ID, bind: bind})
}
