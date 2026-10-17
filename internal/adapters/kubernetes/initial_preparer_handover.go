package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
)

func (s *InitialPreparer) handoverWrite(ctx context.Context, cm *core.ConfigMap, w contracts.InitialPreparationRoot, until time.Time) error {
	if !s.validActivation(w) || w.Activation == nil || w.Activation.Handover == nil {
		return cfg.ErrInvalid
	}
	if e := initialHandoverDeadline(ctx, s.protection.observer.now, until); e != nil {
		return e
	}
	raw, e := json.Marshal(w)
	if e != nil || len(raw) > contracts.InitialPreparationMaxBytes {
		return cfg.ErrInvalid
	}
	next := cm.DeepCopy()
	next.Data = map[string]string{"root.json": string(raw)}
	raw, e = json.Marshal(next)
	if e != nil {
		return cfg.ErrInvalid
	}
	response, e := s.creator.api.Put().AbsPath(s.rootPath()).Param("fieldValidation", "Strict").MaxRetries(0).Body(raw).DoRaw(ctx)
	if e != nil {
		return cfg.ErrUnavailable
	}
	_, got, e := s.decodeRoot(response)
	if e != nil || !equalJSON(got, w) {
		return cfg.ErrChanged
	}
	_, _, _, final, e := s.currentHandover(ctx)
	until = identity.Earlier(until, final)
	if e != nil {
		return e
	}
	return initialHandoverDeadline(ctx, s.protection.observer.now, until)
}

// BeginHandover admits no new workload. The preparation owner must already have
// joined all original CREATE invocations and persisted their positive responses.
// Later processes can consume these exact acknowledgements but cannot invent
// completion by observing a Pod or receiving AlreadyExists on another request.
func (s *InitialPreparer) BeginHandover(ctx context.Context, issuer InitialProviderIssuer) (contracts.InitialPreparationRoot, error) {
	var zero contracts.InitialPreparationRoot
	if !s.HandoverEnabled() || ctx == nil || issuer == nil {
		return zero, cfg.ErrInvalid
	}
	s.requestMu.Lock()
	closed := s.requestClosed
	s.requestMu.Unlock()
	if !closed {
		return zero, ErrInitialPreparationRequestsUnresolved
	}
	cm, w, _, until, e := s.currentHandover(ctx)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if w.Activation.Handover != nil {
		return w, nil
	}
	for _, request := range w.Activation.Pod.Requests {
		if request.Completion == nil {
			return zero, ErrInitialPreparationRequestsUnresolved
		}
	}
	_, private, e := s.readPrivate(ctx)
	if e != nil || private.RootUID != w.RootUID || private.SQL == nil || private.SQL.Secret == nil || private.Providers == nil || private.Providers.Projection == nil || private.Providers.Projection.Secret == nil || private.Probe == nil || private.Probe.Issue == nil || private.Probe.Issue.Response == nil {
		return zero, cfg.ErrChanged
	}
	p := private.Providers
	if !private.Probe.CreateClosed || !private.SQL.CreateClosed || !p.Projection.CreateClosed {
		return zero, ErrInitialPreparationRequestsUnresolved
	}
	if p.Wrap == nil || p.Wrap.Response == nil || p.Unwrap == nil || p.Unwrap.Response == nil {
		return zero, cfg.ErrChanged
	}
	now := s.protection.observer.now()
	bound := w.Activation.Credentials
	if now.Before(bound.NotBefore) || !now.Before(bound.NotAfter) || !now.Before(private.Probe.Issue.Response.ExpiresAt) || !now.Before(p.Wrap.Response.ExpiresAt) || !now.Before(p.Unwrap.Response.ExpiresAt) {
		return zero, cfg.ErrUnavailable
	}
	until = identity.Earlier(until, identity.Earlier(bound.NotAfter, identity.Earlier(private.Probe.Issue.Response.ExpiresAt, identity.Earlier(p.Wrap.Response.ExpiresAt, p.Unwrap.Response.ExpiresAt))))
	ctx, done := context.WithDeadline(ctx, until)
	defer done()
	if e = issuer.Verify(ctx, "wrap", *p.Wrap, p.Parent, *p.Wrap.Response); e != nil {
		return zero, cfg.ErrUnavailable
	}
	if e = issuer.Verify(ctx, "unwrap", *p.Unwrap, p.Parent, *p.Unwrap.Response); e != nil {
		return zero, cfg.ErrUnavailable
	}
	// Re-read the immutable original SQL/projection objects under the same native
	// proof. This is verification, never target creation or credential issuance.
	files, e := s.handoverProjectionFiles(ctx, w, private)
	if e != nil {
		return zero, e
	}
	defer func() {
		for _, b := range files {
			clear(b)
		}
	}()
	ref, e := s.readProviderProjection(ctx, *p.Projection, files)
	if e != nil {
		return zero, e
	}
	id, e := prepUUID()
	if e != nil {
		return zero, e
	}
	entry := w.Activation.Inputs.Creates[initialPreparationConfigurationIndex]
	w.Activation.Handover = &contracts.InitialPreparationHandover{OperationID: id, StartupDigest: bound.StartupDigest, Input: contracts.WorkerObjectReference{Name: entry.Name, UID: entry.Receipt.UID}, Credentials: ref, ReviewedAt: now.UTC().Truncate(time.Microsecond)}
	if e = s.handoverWrite(ctx, cm, w, until); e != nil {
		return zero, e
	}
	return w, nil
}

func (s *InitialPreparer) handoverProjectionFiles(ctx context.Context, w contracts.InitialPreparationRoot, state contracts.InitialPreparationPrivateState) (map[string][]byte, error) {
	ref := state.SQL.Secret
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/secrets/"+ref.Name, nil)
	if e != nil {
		return nil, cfg.ErrUnavailable
	}
	defer clear(raw)
	var sqlSecret core.Secret
	if strictGuardJSON(raw, &sqlSecret) != nil {
		return nil, cfg.ErrChanged
	}
	defer func() {
		for _, v := range sqlSecret.Data {
			clear(v)
		}
	}()
	if sqlSecret.APIVersion != "v1" || sqlSecret.Kind != "Secret" || sqlSecret.Type != core.SecretTypeOpaque || sqlSecret.Immutable == nil || !*sqlSecret.Immutable || !ownerMetadata(sqlSecret.ObjectMeta, s.plan.Workload.Namespace, ref.Name, ref.UID) || len(sqlSecret.OwnerReferences) != 0 || len(sqlSecret.Data) != 1 || len(sqlSecret.StringData) != 0 {
		return nil, cfg.ErrChanged
	}
	sql, e := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(sqlSecret.Data["state.json"]))
	binding := w.Activation.Credentials
	if e != nil || sql.Format != contracts.InitialSQLCredentialsFormat || sql.InstallationID != s.plan.InstallationID || sql.PlanDigest != binding.StartupDigest || !sql.NotBefore.Equal(binding.NotBefore) || !sql.NotAfter.Equal(binding.NotAfter) {
		return nil, cfg.ErrChanged
	}
	material, e := s.readProviderMaterial(ctx)
	if e != nil || material.StorageUseUntil.Before(binding.NotAfter) {
		return nil, cfg.ErrUnavailable
	}
	p := state.Providers
	files := map[string][]byte{"audit-wrap.token": []byte(p.Wrap.Response.Token), "audit-unwrap.token": []byte(p.Unwrap.Response.Token), "kube-probe.token": []byte(state.Probe.Issue.Response.Token)}
	for name, v := range map[string]any{"sql-prepare.json": sql.Preparation, "sql-audit.json": sql.Audit, "sql-activate.json": sql.Activation, "audit-storage.json": material.Storage} {
		b, e := json.Marshal(v)
		if e != nil {
			for _, v := range files {
				clear(v)
			}
			return nil, cfg.ErrInvalid
		}
		files[name] = b
	}
	if _, e = s.providerProjectionData(files, material.RegistryConfig); e != nil {
		for _, b := range files {
			clear(b)
		}
		return nil, e
	}
	return files, nil
}
