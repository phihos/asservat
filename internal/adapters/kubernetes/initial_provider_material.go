package kubernetes

import (
	"bytes"
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
)

func (s *InitialPreparer) ProviderInputsEnabled() bool { return s != nil && s.providers != nil }
func initialProviderASCII(s string, limit int) bool {
	if len(s) < 1 || len(s) > limit {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func validInitialProviderMaterial(v contracts.InitialProviderMaterial, installation, request string, now time.Time) bool {
	return v.Format == contracts.InitialProviderMaterialFormat && v.InstallationID == installation && v.RequestID == request && initialProviderASCII(v.IssuerToken, contracts.InitialProviderTokenMaxBytes) && initialProviderASCII(v.Storage.AccessKeyID, 256) && initialProviderASCII(v.Storage.SecretAccessKey, 1024) && (v.Storage.SessionToken == "" || initialProviderASCII(v.Storage.SessionToken, 4096)) && !v.StorageUseUntil.IsZero() && v.StorageUseUntil.Location() == time.UTC && now.Before(v.StorageUseUntil)
}
func (s *InitialPreparer) readProviderMaterial(ctx context.Context) (contracts.InitialProviderMaterial, error) {
	var zero contracts.InitialProviderMaterial
	if !s.ProviderInputsEnabled() {
		return zero, cfg.ErrInvalid
	}
	ref := s.providers.Material
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.BootstrapNamespace.Name+"/secrets/"+ref.Name, nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var secret core.Secret
	if strictGuardJSON(raw, &secret) != nil {
		return zero, cfg.ErrChanged
	}
	for _, b := range secret.Data {
		defer clear(b)
	}
	if secret.APIVersion != "v1" || secret.Kind != "Secret" || secret.Type != core.SecretTypeOpaque || !ownerMetadata(secret.ObjectMeta, s.plan.BootstrapNamespace.Name, ref.Name, ref.UID) || secret.Immutable == nil || !*secret.Immutable || len(secret.OwnerReferences) != 0 || len(secret.Data) != 1 || len(secret.StringData) != 0 {
		return zero, cfg.ErrChanged
	}
	v, e := contracts.DecodeInitialProviderMaterial(bytes.NewReader(secret.Data["material.json"]))
	if e != nil || !validInitialProviderMaterial(v, s.plan.InstallationID, s.plan.RequestID, s.protection.observer.now()) || !providerconfig.InitialRegistryMaterial(s.plan.Workload.Image, s.plan.Workload.RegistryAuthentication, v.RegistryConfig) {
		return zero, cfg.ErrChanged
	}
	return v, nil
}

// ReadInitialProviderMaterial is a current exact immutable-source read. It also
// works before declaration so malformed local settings fail before any CREATE.
// Its result grants no issuer/effect authority and must not enter diagnostics.
func (s *InitialPreparer) ReadInitialProviderMaterial(ctx context.Context) (contracts.InitialProviderMaterial, time.Time, error) {
	var zero contracts.InitialProviderMaterial
	if ctx == nil || !s.ProviderInputsEnabled() {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	until, e := s.current(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	v, e := s.readProviderMaterial(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	if v.StorageUseUntil.Before(until) {
		until = v.StorageUseUntil
	}
	if e = s.finish(ctx, until); e != nil {
		return zero, time.Time{}, e
	}
	return v, until, nil
}
