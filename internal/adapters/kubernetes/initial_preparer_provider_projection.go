package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// PersistProviderProjection creates the exact seven private files consumed by
// initial-install. It never copies the bootstrap issuer or SQL maintenance
// credential. The writer token remains the existing bounded kubelet projection.
func (b *InitialPreparationCredentialBinder) PersistProviderProjection(ctx context.Context, issuer InitialProviderIssuer) (InitialPreparedSQLState, error) {
	var zero InitialPreparedSQLState
	if b == nil || ctx == nil || issuer == nil || !b.preparer.ProviderInputsEnabled() {
		return zero, cfg.ErrInvalid
	}
	s := b.preparer
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	probe, e := s.PrepareProbe(ctx)
	if e != nil {
		return zero, e
	}
	defer clear(probe.Token)
	_, binding, until, e := b.Bind(ctx)
	if e != nil {
		return zero, e
	}
	until = identity.Earlier(until, probe.ValidUntil)
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if !s.protection.observer.now().Before(binding.NotAfter) {
		return zero, cfg.ErrUnavailable
	}
	material, e := s.readProviderMaterial(ctx)
	if e != nil || material.StorageUseUntil.Before(binding.NotAfter) {
		return zero, cfg.ErrUnavailable
	}
	root, _, e := s.originalPrivateScope(ctx)
	if e != nil {
		return zero, e
	}
	private, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != root.RootUID || state.SQL == nil || state.SQL.Secret == nil || state.Providers == nil || state.Providers.Wrap == nil || state.Providers.Wrap.Response == nil || state.Providers.Unwrap == nil || state.Providers.Unwrap.Response == nil {
		return zero, cfg.ErrChanged
	}
	p := state.Providers
	if e = issuer.Verify(ctx, "wrap", *p.Wrap, p.Parent, *p.Wrap.Response); e != nil {
		return zero, cfg.ErrUnavailable
	}
	if e = issuer.Verify(ctx, "unwrap", *p.Unwrap, p.Parent, *p.Unwrap.Response); e != nil {
		return zero, cfg.ErrUnavailable
	}
	sqlStore := &InitialCredentialStateStore{protection: b.current.protection, inputUID: b.current.inputUID, installation: b.current.installation, plan: b.plan, name: s.plan.Workload.Credentials + "-sql"}
	raw, e := sqlStore.Read(ctx, *state.SQL.Secret)
	if e != nil {
		return zero, e
	}
	defer clear(raw)
	sql, e := contracts.DecodeInitialSQLCredentialState(bytes.NewReader(raw))
	if e != nil || sql.PlanDigest != binding.StartupDigest || !sql.NotBefore.Equal(binding.NotBefore) || !sql.NotAfter.Equal(binding.NotAfter) {
		return zero, cfg.ErrChanged
	}
	files := map[string][]byte{"audit-wrap.token": []byte(p.Wrap.Response.Token), "audit-unwrap.token": []byte(p.Unwrap.Response.Token), "kube-probe.token": append([]byte(nil), probe.Token...)}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	for name, v := range map[string]any{"sql-prepare.json": sql.Preparation, "sql-audit.json": sql.Audit, "sql-activate.json": sql.Activation, "audit-storage.json": material.Storage} {
		data, e := json.Marshal(v)
		if e != nil {
			return zero, cfg.ErrInvalid
		}
		files[name] = data
	}
	secretType, e := s.providerProjectionData(files, material.RegistryConfig)
	if e != nil {
		return zero, e
	}
	fresh := false
	if p.Projection == nil {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		next := state
		copy := *p
		copy.Projection = &contracts.InitialPreparationSQLState{OperationID: id}
		next.Providers = &copy
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, e
		}
		fresh = true
		private, state, e = s.readPrivate(ctx)
		if e != nil {
			return zero, e
		}
		p = state.Providers
	}
	if fresh {
		if e = s.finish(ctx, until); e != nil {
			return zero, e
		}
		object := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.plan.Workload.Credentials, Namespace: s.plan.Workload.Namespace}, Type: secretType, Immutable: ptr.To(true), Data: files}
		s.creator.stamp(&object.ObjectMeta)
		object.Annotations[initialPreparationOperationAnnotation] = p.Projection.OperationID
		reply, err := s.postPreparationSecret(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/secrets", &object)
		if err == nil {
			s.keepSecretCreateResponse(p.Projection.OperationID, reply, &object, until)
		}
		clear(reply)
		if err == cfg.ErrDenied {
			return zero, err
		}
	}
	ref, e := s.readProviderProjection(ctx, *p.Projection, files)
	if e != nil {
		return zero, e
	}
	if p.Projection.Secret == nil {
		next := state
		copy := *p
		projection := *p.Projection
		projection.Secret = &ref
		projection.CreateClosed = s.secretCreateClosed(projection.OperationID, ref)
		copy.Projection = &projection
		next.Providers = &copy
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, e
		}
	}
	final, e := b.current.current(ctx, true)
	until = identity.Earlier(until, final)
	if e != nil {
		return zero, e
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	return InitialPreparedSQLState{Secret: ref, ValidUntil: until}, nil
}
func (s *InitialPreparer) readProviderProjection(ctx context.Context, claim contracts.InitialPreparationSQLState, files map[string][]byte) (contracts.WorkerObjectReference, error) {
	var zero contracts.WorkerObjectReference
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/secrets/"+s.plan.Workload.Credentials, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return zero, cfg.ErrChanged
	}
	for _, data := range secret.Data {
		defer clear(data)
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != s.providerProjectionType() || secret.Immutable == nil || !*secret.Immutable || secret.Namespace != s.plan.Workload.Namespace || !s.creator.owns(secret.ObjectMeta, s.plan.Workload.Credentials) || len(secret.Annotations) != 3 || secret.Annotations[initialPreparationOperationAnnotation] != claim.OperationID || len(secret.Labels) != 0 || len(secret.OwnerReferences) != 0 || len(secret.Finalizers) != 0 || len(secret.StringData) != 0 || len(secret.Data) != len(files) {
		return zero, cfg.ErrChanged
	}
	for name, data := range files {
		if !bytes.Equal(secret.Data[name], data) {
			return zero, cfg.ErrChanged
		}
	}
	ref := contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
	if claim.Secret != nil && *claim.Secret != ref {
		return zero, cfg.ErrChanged
	}
	return ref, nil
}
