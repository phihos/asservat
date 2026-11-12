package bootstrap

import (
	"bytes"
	"context"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
)

// Called only after positive original seed absence. A fully bundled provider
// pair needs no operator credential file. Mixed/external selections keep their
// explicit source; no unavailable backend silently selects a bundled fallback.
func (d *initialBootstrapProcess) firstMaterial(ctx context.Context, input *os.Root) (contracts.InitialBootstrapMaterial, error) {
	material := contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat}
	if d.services.KeyService == nil || d.services.ObjectStore == nil {
		raw, err := mounts.Read(ctx, input, "provider-material.json", contracts.InitialProviderMaterialMaxBytes)
		if err != nil {
			return material, mounts.ErrUnavailable
		}
		fragment, err := contracts.DecodeInitialBootstrapProviderInput(bytes.NewReader(raw))
		clear(raw)
		if err != nil {
			return contracts.InitialBootstrapMaterial{}, mounts.ErrUnavailable
		}
		material, err = initialProviderFragmentMaterial(fragment, d.services, time.Now())
		if err != nil {
			return contracts.InitialBootstrapMaterial{}, err
		}
	}
	if d.services.KeyService != nil {
		if material.IssuerToken != "" {
			return contracts.InitialBootstrapMaterial{}, mounts.ErrUnavailable
		}
		provider, err := openInitialOpenBaoProvider(ctx, input, *d.services.KeyService, d.inputs.kubernetes("administrator-token"))
		if err != nil {
			return contracts.InitialBootstrapMaterial{}, err
		}
		defer provider.Close()
		material.SetupToken = string(provider.Token)
		selected := provider.Identity
		material.BundledIdentity = &selected
		if d.services.ObjectStore != nil {
			material.StorageUseUntil = selected.SetupParent.ExpiresAt.Add(-contracts.BundledInitialProviderSafetyMargin)
		}
	}
	if d.services.ObjectStore != nil {
		if err := generateInitialSeaweedStorage(&material); err != nil {
			return contracts.InitialBootstrapMaterial{}, err
		}
	}
	if ctx.Err() != nil || !time.Now().Before(material.StorageUseUntil) {
		return contracts.InitialBootstrapMaterial{}, mounts.ErrUnavailable
	}
	return material, nil
}

// Validate EVERY external dependency before opening a selected provider or
// generating private material. Missing fields are determined by the existing
// public selection, never guessed from an unavailable backend.
func initialProviderFragmentMaterial(v contracts.InitialBootstrapProviderInput, selected initialBootstrapServices, now time.Time) (contracts.InitialBootstrapMaterial, error) {
	var zero contracts.InitialBootstrapMaterial
	if v.Format != contracts.InitialBootstrapMaterialFormat || now.IsZero() {
		return zero, mounts.ErrUnavailable
	}
	if selected.KeyService == nil {
		if !kms.ValidProviderToken([]byte(v.IssuerToken)) || len(v.IssuerToken) > contracts.InitialProviderTokenMaxBytes {
			return zero, mounts.ErrUnavailable
		}
	} else if v.IssuerToken != "" {
		return zero, mounts.ErrUnavailable
	}
	if selected.ObjectStore == nil {
		if v.Storage == nil || !initialProviderInputText(v.Storage.AccessKeyID, 256) || !initialProviderInputText(v.Storage.SecretAccessKey, 1024) || v.Storage.SessionToken != "" && !initialProviderInputText(v.Storage.SessionToken, 4096) {
			return zero, mounts.ErrUnavailable
		}
	} else if v.Storage != nil {
		return zero, mounts.ErrUnavailable
	}
	// Every mixed/external fragment declares its original finite storage use
	// interval; the fully bundled path derives that same bound from setup.
	if v.StorageUseUntil.Year() < 2020 || v.StorageUseUntil.Year() > 9998 || !now.Before(v.StorageUseUntil) {
		return zero, mounts.ErrUnavailable
	}
	result := contracts.InitialBootstrapMaterial{Format: v.Format, IssuerToken: v.IssuerToken, StorageUseUntil: v.StorageUseUntil.UTC()}
	if v.Storage != nil {
		result.Storage = *v.Storage
	}
	return result, nil
}
func initialProviderInputText(value string, max int) bool {
	return len(value) <= max && kms.ValidProviderToken([]byte(value))
}
