package kubernetes

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// InitialPreparedSQLState is exact immutable private persistence provenance.
// It is not SQL provisioning, activation or current recovery authority.
type InitialPreparedSQLState struct {
	Secret     contracts.WorkerObjectReference
	ValidUntil time.Time
}

// PersistSQLState preserves one original target Secret CREATE across process
// loss. The actual SQL codec belongs to the caller; this boundary independently
// matches its passwords/dates/plan to the original retained material and binding.
func (b *InitialPreparationCredentialBinder) PersistSQLState(ctx context.Context, payload []byte) (InitialPreparedSQLState, error) {
	var zero InitialPreparedSQLState
	if b == nil || ctx == nil || !b.preparer.PrivateInputsEnabled() || len(payload) == 0 || len(payload) > 4096 {
		return zero, cfg.ErrInvalid
	}
	s := b.preparer
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	payload = append([]byte(nil), payload...)
	defer clear(payload)
	material, binding, until, e := b.Bind(ctx)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	value, e := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(payload))
	if e != nil || value.Format != contracts.InitialSQLCredentialsFormat || value.InstallationID != s.plan.InstallationID || value.PlanDigest != binding.StartupDigest || value.PlanDigest != hex.EncodeToString(b.plan[:]) || !value.NotBefore.Equal(binding.NotBefore) || !value.NotAfter.Equal(binding.NotAfter) || value.Preparation.Password != material.PreparationPassword || value.Audit.Password != material.AuditPassword || value.Activation.Password != material.ActivationPassword {
		return zero, cfg.ErrChanged
	}
	if now := s.protection.observer.now(); now.Before(value.NotBefore) || !now.Before(value.NotAfter) {
		return zero, cfg.ErrUnavailable
	}
	root, _, e := s.originalPrivateScope(ctx)
	if e != nil {
		return zero, e
	}
	private, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != root.RootUID || state.Probe == nil || state.Probe.Issue == nil || state.Probe.Issue.Response == nil {
		return zero, cfg.ErrChanged
	}
	store := &InitialCredentialStateStore{protection: b.current.protection, inputUID: b.current.inputUID, installation: b.current.installation, plan: b.plan, name: s.plan.Workload.Credentials + "-sql"}
	fresh := false
	if state.SQL == nil {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		next := state
		next.SQL = &contracts.InitialPreparationSQLState{OperationID: id}
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, e
		}
		fresh = true
		private, state, e = s.readPrivate(ctx)
		if e != nil {
			return zero, e
		}
	}
	var ref contracts.WorkerObjectReference
	if state.SQL.Secret != nil {
		ref = *state.SQL.Secret
		raw, e := store.Read(ctx, ref)
		defer clear(raw)
		if e != nil {
			return zero, e
		}
		if !bytes.Equal(raw, payload) {
			return zero, cfg.ErrChanged
		}
	} else {
		if fresh {
			var closed bool
			ref, closed, e = store.createWithCompletion(ctx, payload)
			if closed {
				s.keepSecretCompletion(state.SQL.OperationID, ref)
			}
		} else {
			ref, e = store.ResolveCreate(ctx, payload)
		}
		if e != nil {
			return zero, e
		}
		next := state
		sql := *state.SQL
		sql.Secret = &ref
		sql.CreateClosed = s.secretCreateClosed(sql.OperationID, ref)
		next.SQL = &sql
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, e
		}
	}
	if _, e = b.current.current(ctx, true); e != nil {
		return zero, e
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	return InitialPreparedSQLState{Secret: ref, ValidUntil: until}, nil
}
