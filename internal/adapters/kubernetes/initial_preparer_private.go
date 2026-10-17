package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func (s *InitialPreparer) PrivateInputsEnabled() bool { return s != nil && s.plan.PrivateState != nil }

func validInitialPrivateTime(v time.Time) bool {
	return !v.IsZero() && v.Location() == time.UTC && v.Equal(v.Truncate(time.Microsecond))
}
func (s *InitialPreparer) validPrivateState(v contracts.InitialPreparationPrivateState) bool {
	if v.Format != contracts.InitialPreparationPrivateFormat || v.InstallationID != s.plan.InstallationID || v.RequestID != s.plan.RequestID {
		return false
	}
	if v.RootUID == "" {
		return v.PlanDigest == "" && v.Probe == nil && v.SQL == nil && v.Providers == nil
	}
	if !authorization.UUID(v.RootUID) || v.PlanDigest != preparationPlanDigest(s.plan) {
		return false
	}
	if v.SQL != nil {
		if v.Probe == nil || v.Probe.Issue == nil || v.Probe.Issue.Response == nil || !authorization.UUID(v.SQL.OperationID) || v.SQL.OperationID == v.Probe.AnchorOperationID || v.SQL.OperationID == v.Probe.Issue.ID {
			return false
		}
		if v.SQL.CreateClosed && (!s.HandoverEnabled() || v.SQL.Secret == nil) {
			return false
		}
		if v.SQL.Secret != nil && (v.SQL.Secret.Name != s.plan.Workload.Credentials+"-sql" || !authorization.UUID(v.SQL.Secret.UID)) {
			return false
		}
	}
	if !s.validPrivateProviders(v) {
		return false
	}
	if v.Probe == nil {
		return true
	}
	p := v.Probe
	if p.CreateClosed && (!s.HandoverEnabled() || p.Anchor == nil) {
		return false
	}
	if !authorization.UUID(p.AnchorOperationID) || !validPreparerReceipt(p.Anchor) {
		return false
	}
	if p.Issue == nil {
		return true
	}
	i := p.Issue
	if p.Anchor == nil || !authorization.UUID(i.ID) || i.Audience != s.plan.ProbeAudience || !validInitialPrivateTime(i.StartedAt) || !validInitialPrivateTime(i.Until) || !validInitialPrivateTime(i.ExpiresBefore) || !i.StartedAt.Before(i.Until) || i.Until.Sub(i.StartedAt) > 5*time.Second || !i.ExpiresBefore.Equal(i.StartedAt.Add(605*time.Second)) {
		return false
	}
	if i.Response == nil {
		return true
	}
	response := i.Response
	return identity.Text(response.Token, 8192) && len(response.Token) >= 32 && validInitialPrivateTime(response.ExpiresAt) && response.ExpiresAt.After(i.Until) && !response.ExpiresAt.After(i.ExpiresBefore)
}
func (s *InitialPreparer) privatePath() string {
	return "/api/v1/namespaces/" + s.plan.BootstrapNamespace.Name + "/secrets/" + s.plan.PrivateState.Name
}
func (s *InitialPreparer) decodePrivate(raw []byte) (*core.Secret, contracts.InitialPreparationPrivateState, error) {
	var zero contracts.InitialPreparationPrivateState
	var secret core.Secret
	if s == nil || s.plan.PrivateState == nil || strictGuardJSON(raw, &secret) != nil {
		return nil, zero, cfg.ErrChanged
	}
	for _, b := range secret.Data {
		defer clear(b)
	}
	ref := s.plan.PrivateState
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != core.SecretTypeOpaque || !ownerMetadata(secret.ObjectMeta, s.plan.BootstrapNamespace.Name, ref.Name, ref.UID) || secret.Immutable != nil && *secret.Immutable || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.Data) != 1 || len(secret.StringData) != 0 || secret.Annotations[initialNamespaceInstallationAnnotation] != s.plan.InstallationID || secret.Annotations[initialNamespaceRequestAnnotation] != s.plan.RequestID {
		return nil, zero, cfg.ErrChanged
	}
	v, e := contracts.DecodeInitialPreparationPrivateState(bytes.NewReader(secret.Data["state.json"]))
	if e != nil || !s.validPrivateState(v) {
		return nil, zero, cfg.ErrChanged
	}
	// Metadata is retained for CAS; decoded raw credential buffers are cleared.
	secret.Data = nil
	return &secret, v, nil
}
func (s *InitialPreparer) readPrivate(ctx context.Context) (*core.Secret, contracts.InitialPreparationPrivateState, error) {
	var zero contracts.InitialPreparationPrivateState
	if s == nil || s.plan.PrivateState == nil {
		return nil, zero, cfg.ErrInvalid
	}
	raw, e := s.creator.raw(ctx, s.privatePath(), nil)
	if e != nil {
		return nil, zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	return s.decodePrivate(raw)
}

// The state machine is closed: root binding, one anchor intent/receipt and one
// token claim/response, then one SQL-state intent/receipt. Exact idempotent
// copies are allowed, but no transition
// removes a claim, replaces an identity, renews a deadline or rewrites a token.
func (s *InitialPreparer) privateTransition(old, next contracts.InitialPreparationPrivateState) bool {
	if !s.validPrivateState(old) || !s.validPrivateState(next) {
		return false
	}
	if equalJSON(old, next) {
		return true
	}
	if s.privateCompletionTransition(old, next) {
		return true
	}
	copy := old
	if old.RootUID == "" {
		copy.RootUID = next.RootUID
		copy.PlanDigest = next.PlanDigest
		return next.RootUID != "" && equalJSON(copy, next)
	}
	if old.Probe == nil {
		copy.Probe = next.Probe
		return next.Probe != nil && next.Probe.Anchor == nil && next.Probe.Issue == nil && equalJSON(copy, next)
	}
	if next.Probe == nil {
		return false
	}
	p := *old.Probe
	copy.Probe = &p
	if p.Anchor == nil {
		p.Anchor = next.Probe.Anchor
		p.CreateClosed = next.Probe.CreateClosed
		return p.Anchor != nil && equalJSON(copy, next)
	}
	if p.Issue == nil {
		p.Issue = next.Probe.Issue
		return p.Issue != nil && p.Issue.Response == nil && equalJSON(copy, next)
	}
	if next.Probe.Issue == nil {
		return false
	}
	i := *p.Issue
	p.Issue = &i
	if i.Response == nil {
		i.Response = next.Probe.Issue.Response
		return i.Response != nil && equalJSON(copy, next)
	}
	if old.SQL == nil {
		copy.SQL = next.SQL
		return next.SQL != nil && next.SQL.Secret == nil && equalJSON(copy, next)
	}
	if old.SQL.Secret == nil && next.SQL != nil {
		sql := *old.SQL
		sql.Secret = next.SQL.Secret
		sql.CreateClosed = next.SQL.CreateClosed
		copy.SQL = &sql
		return sql.Secret != nil && equalJSON(copy, next)
	}
	return s.privateProviderTransition(old, next)
}
func (s *InitialPreparer) writePrivate(ctx context.Context, secret *core.Secret, old, next contracts.InitialPreparationPrivateState, until time.Time) error {
	if secret == nil || !s.privateTransition(old, next) {
		return cfg.ErrChanged
	}
	if e := s.finish(ctx, until); e != nil {
		return e
	}
	payload, e := json.Marshal(next)
	if e != nil || len(payload) > contracts.InitialPreparationPrivateMaxBytes {
		return cfg.ErrInvalid
	}
	defer clear(payload)
	out := secret.DeepCopy()
	out.Data = map[string][]byte{"state.json": payload}
	raw, e := json.Marshal(out)
	if e != nil {
		return cfg.ErrInvalid
	}
	defer clear(raw)
	reply, e := s.creator.api.Put().AbsPath(s.privatePath()).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).DoRaw(ctx)
	defer clear(reply)
	if e != nil {
		return cfg.ErrUnavailable
	}
	_, got, e := s.decodePrivate(reply)
	if e != nil || !equalJSON(got, next) {
		return cfg.ErrChanged
	}
	return s.finish(ctx, until)
}

// OpenPrivateState binds the original root once. This is private provenance,
// not permission to issue a credential or skip the original guard checks.
func (s *InitialPreparer) OpenPrivateState(ctx context.Context) (contracts.InitialPreparationPrivateState, time.Time, error) {
	var zero contracts.InitialPreparationPrivateState
	if s == nil || s.plan.PrivateState == nil || ctx == nil {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	defer joined()
	until, e := s.current(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	_, root, e := s.read(ctx)
	if e != nil || root.RootUID == "" || root.Phase != "declared" || root.Activation == nil || root.Activation.Pod == nil || root.Activation.Pod.Receipt == nil {
		return zero, time.Time{}, cfg.ErrChanged
	}
	secret, v, e := s.readPrivate(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	if v.RootUID == "" {
		next := v
		next.RootUID = root.RootUID
		next.PlanDigest = root.PlanDigest
		if e = s.writePrivate(ctx, secret, v, next, until); e != nil {
			return zero, time.Time{}, e
		}
		v = next
	}
	if v.RootUID != root.RootUID || v.PlanDigest != root.PlanDigest {
		return zero, time.Time{}, cfg.ErrChanged
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, time.Time{}, e
	}
	return v, until, nil
}
