package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

// Completion belongs to the original, acknowledged CREATE response. Neither an
// exact GET nor another request's 409 can populate this bounded private map.
func (s *InitialPreparer) keepSecretCompletion(id string, ref contracts.WorkerObjectReference) {
	if !s.HandoverEnabled() {
		return
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if s.requestClosed {
		return
	}
	if s.secretCompletions == nil {
		s.secretCompletions = map[string]contracts.WorkerObjectReference{}
	}
	if old, ok := s.secretCompletions[id]; ok && old != ref {
		return
	}
	if len(s.secretCompletions) < 3 {
		s.secretCompletions[id] = ref
	}
}
func (s *InitialPreparer) secretCreateClosed(id string, ref contracts.WorkerObjectReference) bool {
	if !s.HandoverEnabled() {
		return false
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	got, ok := s.secretCompletions[id]
	return ok && got == ref
}
func (s *InitialPreparer) keepSecretCreateResponse(id string, raw []byte, want *core.Secret, until time.Time) {
	if !s.HandoverEnabled() || !s.protection.observer.now().Before(until) {
		return
	}
	var got core.Secret
	if strictGuardJSON(raw, &got) != nil {
		return
	}
	defer func() {
		for _, b := range got.Data {
			clear(b)
		}
	}()
	if got.APIVersion != "v1" || got.Kind != "Secret" || !s.creator.owns(got.ObjectMeta, want.Name) || got.Namespace != want.Namespace || got.Type != want.Type || got.Immutable == nil || !*got.Immutable || len(got.OwnerReferences) != 0 || len(got.Finalizers) != 0 || len(got.StringData) != 0 || !equalJSON(got.Annotations, want.Annotations) || !equalJSON(got.Labels, want.Labels) || !equalJSON(got.Data, want.Data) {
		return
	}
	s.keepSecretCompletion(id, contracts.WorkerObjectReference{Name: got.Name, UID: string(got.UID)})
}

// The only additional state transition is false->true on a previously pinned
// receipt. The writing producer must separately possess its own positive result.
func (s *InitialPreparer) privateCompletionTransition(old, next contracts.InitialPreparationPrivateState) bool {
	if !s.HandoverEnabled() {
		return false
	}
	copy := old
	changed := false
	if old.Probe != nil && next.Probe != nil && !old.Probe.CreateClosed && next.Probe.CreateClosed && old.Probe.Anchor != nil {
		p := *old.Probe
		p.CreateClosed = true
		copy.Probe = &p
		changed = true
	}
	if old.SQL != nil && next.SQL != nil && !old.SQL.CreateClosed && next.SQL.CreateClosed && old.SQL.Secret != nil {
		p := *old.SQL
		p.CreateClosed = true
		copy.SQL = &p
		changed = true
	}
	if old.Providers != nil && next.Providers != nil && old.Providers.Projection != nil && next.Providers.Projection != nil && !old.Providers.Projection.CreateClosed && next.Providers.Projection.CreateClosed && old.Providers.Projection.Secret != nil {
		p := *old.Providers
		q := *p.Projection
		q.CreateClosed = true
		p.Projection = &q
		copy.Providers = &p
		changed = true
	}
	return changed && equalJSON(copy, next)
}
func (s *InitialPreparer) persistSecretCompletions(ctx context.Context, until time.Time) error {
	secret, state, e := s.readPrivate(ctx)
	if e != nil {
		return e
	}
	next := state
	if p := state.Probe; p != nil && p.Anchor != nil && !p.CreateClosed && s.secretCreateClosed(p.AnchorOperationID, contracts.WorkerObjectReference{Name: s.probeAnchorName(), UID: p.Anchor.UID}) {
		q := *p
		q.CreateClosed = true
		next.Probe = &q
	}
	if p := state.SQL; p != nil && p.Secret != nil && !p.CreateClosed && s.secretCreateClosed(p.OperationID, *p.Secret) {
		q := *p
		q.CreateClosed = true
		next.SQL = &q
	}
	if p := state.Providers; p != nil && p.Projection != nil && p.Projection.Secret != nil && !p.Projection.CreateClosed && s.secretCreateClosed(p.Projection.OperationID, *p.Projection.Secret) {
		q := *p
		r := *p.Projection
		r.CreateClosed = true
		q.Projection = &r
		next.Providers = &q
	}
	if !equalJSON(state, next) {
		if e = s.writePrivate(ctx, secret, state, next, until); e != nil {
			return e
		}
	}
	if next.Probe == nil || !next.Probe.CreateClosed || next.SQL == nil || !next.SQL.CreateClosed || next.Providers == nil || next.Providers.Projection == nil || !next.Providers.Projection.CreateClosed {
		return ErrInitialPreparationRequestsUnresolved
	}
	if e = s.finish(ctx, until); e != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *InitialPreparer) postPreparationSecret(ctx context.Context, path string, v *core.Secret) ([]byte, error) {
	if !s.HandoverEnabled() {
		return s.creator.post(ctx, path, v)
	}
	if e := s.creator.administrator(ctx); e != nil {
		return nil, e
	}
	body, e := json.Marshal(v)
	if e != nil {
		return nil, cfg.ErrInvalid
	}
	defer clear(body)
	reply := s.creator.api.Post().AbsPath(path).Param("fieldValidation", "Strict").MaxRetries(0).Body(body).Do(ctx)
	code := 0
	reply.StatusCode(&code)
	raw, e := reply.Raw()
	if e == nil {
		e = reply.Error()
	}
	if e != nil || code != 201 || permissionJSON(raw, permissionPageBytes, 131072) != nil {
		clear(raw)
		if e != nil {
			return nil, permissionError(ctx, e)
		}
		return nil, cfg.ErrUnavailable
	}
	return raw, nil
}
