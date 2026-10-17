package kubernetes

import (
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func (s *InitialPreparer) validSchema(w contracts.InitialPreparationRoot) bool {
	v := w.Schema
	if v == nil {
		return s.plan.SchemaInitialization == "" || len(w.Creates) == 0 && w.Activation == nil
	}
	if s.plan.SchemaInitialization != contracts.InitialSchemaProtocol || w.RootUID == "" || !authorization.UUID(v.AttemptID) || v.Head < 1 || v.Head > 128 || v.DatabaseOID == 0 || !initialHandoverTime(v.PostmasterAt) || !initialHandoverTime(v.ClaimedAt) || v.PostmasterAt.After(v.ClaimedAt) || !identity.Text(v.DDLRole.Name, 63) || v.DDLRole.OID == 0 || s.plan.HistoryManager == nil || v.Manager != *s.plan.HistoryManager || v.DDLRole.OID == v.Manager.OID {
		return false
	}
	digest, e := hex.DecodeString(v.BundleDigest)
	if e != nil || len(digest) != 32 || hex.EncodeToString(digest) != v.BundleDigest {
		return false
	}
	if v.CompletedAt == nil {
		return len(w.Creates) == 0 && w.Activation == nil
	}
	return initialHandoverTime(*v.CompletedAt) && !v.CompletedAt.Before(v.ClaimedAt)
}

// schemaCurrent checks only existing protected bootstrap/final guard authority.
// No database state or journal entry can create current administrator authority.
// historical selects the read-only handover fallback that accepts the
// bridge's retained guard (ADR-187); schema effects keep the original guard.
func (s *InitialPreparer) schemaCurrent(ctx context.Context, historical bool) (*core.ConfigMap, contracts.InitialPreparationRoot, time.Time, error) {
	var zero contracts.InitialPreparationRoot
	if s == nil || s.plan.SchemaInitialization != contracts.InitialSchemaProtocol || ctx == nil {
		return nil, zero, time.Time{}, cfg.ErrInvalid
	}
	start := s.protection.observer.now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	until, e := s.current(ctx)
	if e != nil {
		handover := s.currentHandover
		if historical {
			handover = s.passiveHandover
		}
		cm, w, _, bound, other := handover(ctx)
		bound = identity.Earlier(start.Add(5*time.Second), bound)
		if other != nil || w.Schema == nil || w.Schema.CompletedAt == nil {
			return nil, zero, time.Time{}, cfg.ErrUnavailable
		}
		if e = initialHandoverDeadline(ctx, s.protection.observer.now, bound); e != nil {
			return nil, zero, time.Time{}, e
		}
		return cm, w, bound, nil
	}
	cm, w, e := s.read(ctx)
	if e != nil {
		return nil, zero, time.Time{}, e
	}
	if e = initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return nil, zero, time.Time{}, e
	}
	return cm, w, until, nil
}

// ReadInitialSchema is historical metadata only. Open must have already pinned
// the original root; it never creates or adopts a missing root here.
func (s *InitialPreparer) ReadInitialSchema(ctx context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	_, w, until, e := s.schemaCurrent(ctx, true)
	return w, until, e
}

// ClaimInitialSchema retains one positively observed empty-database binding.
// The SQL owner must still hold its original database session lock and deadline.
// Calling this method by itself creates no SQL or recovery authority.
func (s *InitialPreparer) ClaimInitialSchema(ctx context.Context, v contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	var zero contracts.InitialPreparationRoot
	cm, w, until, e := s.schemaCurrent(ctx, false)
	if e != nil {
		return zero, time.Time{}, e
	}
	if v.AttemptID != "" || v.CompletedAt != nil || !v.ClaimedAt.IsZero() {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	if w.Schema != nil {
		return zero, time.Time{}, cfg.ErrChanged
	}
	if w.Phase != "declaring" || len(w.Creates) != 0 || w.Activation != nil {
		return zero, time.Time{}, cfg.ErrChanged
	}
	v.AttemptID, e = prepUUID()
	if e != nil {
		return zero, time.Time{}, e
	}
	v.ClaimedAt = s.protection.observer.now().UTC().Truncate(time.Microsecond)
	w.Schema = &v
	if !s.validSchema(w) {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if e = s.write(ctx, cm, w, until); e != nil {
		return zero, time.Time{}, e
	}
	return w, until, nil
}

// CompleteInitialSchema acknowledges separately verified exact SQL history and
// manager grants. A lost acknowledgement can be retried only after the SQL
// owner repeats its independent read under a fresh original current lease.
func (s *InitialPreparer) CompleteInitialSchema(ctx context.Context, expected contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	var zero contracts.InitialPreparationRoot
	cm, w, until, e := s.schemaCurrent(ctx, false)
	if e != nil {
		return zero, time.Time{}, e
	}
	if w.Schema == nil || expected.CompletedAt != nil {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	original := *w.Schema
	original.CompletedAt = nil
	if original != expected {
		return zero, time.Time{}, cfg.ErrChanged
	}
	if w.Schema.CompletedAt != nil {
		return w, until, nil
	}
	now := s.protection.observer.now().UTC().Truncate(time.Microsecond)
	w.Schema.CompletedAt = &now
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if e = s.write(ctx, cm, w, until); e != nil {
		return zero, time.Time{}, e
	}
	return w, until, nil
}
