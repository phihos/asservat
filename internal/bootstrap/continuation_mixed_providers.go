package bootstrap

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

// Only the two mixed selections need operator/provider handoff. Empty retains
// the existing all-bundled and all-external recipe/inbox behavior and bytes.
func (k *InstallerContinuation) mixedProviderMode() string {
	if k.keyService != nil && k.objectStore == nil {
		return contracts.InstallerProviderBundledKeyService
	}
	if k.keyService == nil && k.objectStore != nil {
		return contracts.InstallerProviderBundledObjectStore
	}
	return ""
}
func (k *InstallerContinuation) mixedProviderOutboxMode() string {
	if k.keyService == nil && k.objectStore != nil {
		return contracts.InstallerProviderBundledObjectStore
	}
	return ""
}

func installerRecipeDigest(artifact []byte) string {
	sum := sha256.Sum256(artifact)
	return hex.EncodeToString(sum[:])
}
func (k *InstallerContinuation) awaitMixedProviderData(ctx context.Context, phase int, digest, mode string, tokenRequired bool) (*core.Secret, error) {
	for {
		original, err := kube.ReadMixedInstallerInbox(ctx, k.in.kubernetes("administrator-token"), k.input.Namespace, k.record.Scope.InstallationID, digest, mode)
		if errors.Is(err, cfg.ErrChanged) || errors.Is(err, cfg.ErrInvalid) {
			return nil, err
		}
		if err == nil {
			if string(original.Data[contracts.InstallerInboxPhase]) != strconv.Itoa(phase) {
				clearMixedInstallerData(original.Data)
				return nil, cfg.ErrChanged
			}
			if !tokenRequired || len(original.Data[contracts.InstallerInboxInspectionToken]) != 0 {
				return original, nil
			}
			clearMixedInstallerData(original.Data)
		}
		select {
		case <-ctx.Done():
			return nil, mounts.ErrUnavailable
		case <-time.After(2 * time.Second):
		}
	}
}
func clearMixedInstallerData(data map[string][]byte) {
	for _, raw := range data {
		clear(raw)
	}
}
func mixedInstallerInbox(s *core.Secret) kube.InstallerInbox {
	copy := func(key string) []byte { return bytes.Clone(s.Data[key]) }
	out := kube.InstallerInbox{UID: string(s.UID), InspectionToken: copy(contracts.InstallerInboxInspectionToken), AuditCredential: copy(contracts.InstallerInboxAuditCredential), FederationAuditCredential: copy(contracts.InstallerInboxFederationAuditCredential), PublisherAuditCredential: copy(contracts.InstallerInboxPublisherAuditCredential), EvidenceReadCredential: copy(contracts.InstallerInboxEvidenceReadCredential), DownloadEvidenceCredential: copy(contracts.InstallerInboxDownloadEvidenceCredential), EvidenceDeleteCredential: copy(contracts.InstallerInboxEvidenceDeleteCredential), CleanupAuditCredential: copy(contracts.InstallerInboxCleanupAuditCredential), CleanupVerifyCredential: copy(contracts.InstallerInboxCleanupVerifyCredential)}
	for _, key := range contracts.InstallerInboxPublicFiles(false) {
		if len(s.Data[key]) != 0 {
			if out.Public == nil {
				out.Public = map[string][]byte{}
			}
			out.Public[key] = copy(key)
		}
	}
	for _, key := range contracts.InstallerInboxServingTLSFiles() {
		if len(s.Data[key]) != 0 {
			if out.ServingTLS == nil {
				out.ServingTLS = map[string][]byte{}
			}
			out.ServingTLS[key] = copy(key)
		}
	}
	return out
}
func (k *InstallerContinuation) awaitMixedProviderInbox(ctx context.Context, phase int, digest, mode string) (kube.InstallerInbox, error) {
	original, err := k.awaitMixedProviderData(ctx, phase, digest, mode, true)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clearMixedInstallerData(original.Data)
	return mixedInstallerInbox(original), nil
}
func (k *InstallerContinuation) mixedWorkerProviderInbox(ctx context.Context, in contracts.HubWorkerDeployment, selected contracts.ConfigurationProviderSelection, account contracts.WorkerObjectReference, layout string) (kube.InstallerInbox, error) {
	artifact, err := providerconfig.ConfigurationProviderPairSetupArtifact(in, selected, account, layout, time.Now())
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	mode, digest := k.mixedProviderMode(), installerRecipeDigest(artifact)
	if mode == contracts.InstallerProviderBundledKeyService {
		return k.completeMixedBundledProvider(ctx, 1, artifact)
	}
	if mode != contracts.InstallerProviderBundledObjectStore {
		return kube.InstallerInbox{}, mounts.ErrUnavailable
	}
	credential, err := kube.ReadOrInitializeSeaweedCredential(ctx, k.in.kubernetes("administrator-token"), in.Namespace.Name, selected.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, contracts.SeaweedPrincipalKey{Purpose: "configuration-audit", ScopeID: in.InstallationID})
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	runtime, err := providerconfig.SeaweedRuntimeCredential(credential)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clear(raw)
	original, err := kube.ReadOrCreateMixedInstallerInbox(ctx, k.in.kubernetes("administrator-token"), k.input.Namespace, in.InstallationID, digest, mode, map[string][]byte{contracts.InstallerInboxPhase: []byte("1"), contracts.InstallerInboxAuditCredential: raw})
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clearMixedInstallerData(original.Data)
	if !bytes.Equal(original.Data[contracts.InstallerInboxAuditCredential], raw) {
		return kube.InstallerInbox{}, mounts.ErrUnavailable
	}
	return k.awaitMixedProviderInbox(ctx, 1, digest, mode)
}
func (k *InstallerContinuation) mixedOwnerProviderInbox(ctx context.Context, artifact []byte) (kube.InstallerInbox, error) {
	return k.completeMixedBundledProvider(ctx, 3, artifact)
}
func (k *InstallerContinuation) completeMixedBundledProvider(ctx context.Context, phase int, artifact []byte) (kube.InstallerInbox, error) {
	mode, digest := contracts.InstallerProviderBundledKeyService, installerRecipeDigest(artifact)
	data, err := k.mixedExternalStorageData(ctx, phase, artifact)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clearMixedInstallerData(data)
	original, err := kube.ReadOrCreateMixedInstallerInbox(ctx, k.in.kubernetes("administrator-token"), k.input.Namespace, k.record.Scope.InstallationID, digest, mode, data)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clearMixedInstallerData(original.Data)
	retained := maps.Clone(original.Data)
	delete(retained, contracts.InstallerInboxInspectionToken)
	if !maps.EqualFunc(retained, data, bytes.Equal) {
		return kube.InstallerInbox{}, mounts.ErrUnavailable
	}
	token, err := k.applySmallProvider(ctx, phase, artifact)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clear(token)
	completed, err := kube.CompleteMixedInstallerInbox(ctx, k.in.kubernetes("administrator-token"), k.input.Namespace, k.record.Scope.InstallationID, digest, mode, original, token)
	if err != nil {
		return kube.InstallerInbox{}, err
	}
	defer clearMixedInstallerData(completed.Data)
	return mixedInstallerInbox(completed), nil
}

// Independently enforce the actual recipe's exact private groups before any
// selected provider effect. This does not authorize the artifact itself.
func mixedInstallerDataMatchesRecipe(phase int, artifact []byte, data map[string][]byte) error {
	if string(data[contracts.InstallerInboxPhase]) != strconv.Itoa(phase) {
		return mounts.ErrUnavailable
	}
	expected := map[string]bool{contracts.InstallerInboxPhase: true, contracts.InstallerInboxAuditCredential: true}
	if phase == 3 {
		p, err := readInstallerProviderMaterialPlan(artifact)
		if err != nil {
			return err
		}
		present := func(v json.RawMessage) bool { return len(v) != 0 && string(v) != "null" && string(v) != "false" }
		groups := []struct {
			enabled bool
			keys    []string
		}{
			{present(p.Federation), []string{contracts.InstallerInboxFederationAuditCredential}},
			{present(p.Publisher), []string{contracts.InstallerInboxPublisherAuditCredential, contracts.InstallerInboxEvidenceReadCredential}},
			{present(p.Downloads), []string{contracts.InstallerInboxDownloadEvidenceCredential}},
			{present(p.Deletion), []string{contracts.InstallerInboxEvidenceDeleteCredential}},
			{present(p.Cleanup), []string{contracts.InstallerInboxCleanupAuditCredential, contracts.InstallerInboxCleanupVerifyCredential}},
			// The serving pair is optional here; installer continuation
			// requires it unless the exposure terminates TLS at a proxy.
			{p.Public, contracts.InstallerInboxPublicFiles(true)},
		}
		for _, group := range groups {
			if group.enabled {
				for _, key := range group.keys {
					expected[key] = true
				}
			}
		}
		serving := map[string][]byte{}
		for i, host := range []string{p.ServingTLS.FederationServerName, p.ServingTLS.KeyServiceServerName} {
			if host != "" {
				for _, key := range contracts.InstallerInboxServingTLSFiles()[i*3 : i*3+3] {
					expected[key] = true
					serving[key] = data[key]
				}
			}
		}
		if kube.ValidateInstallerServingTLSMaterial(p.ServingTLS, serving, time.Now()) != nil {
			return mounts.ErrUnavailable
		}
		if p.Public {
			public := map[string][]byte{}
			for _, key := range contracts.InstallerInboxPublicFiles(false) {
				if raw, ok := data[key]; ok {
					public[key] = raw
				}
			}
			if !contracts.InstallerPublicFilesShape(public) {
				return mounts.ErrUnavailable
			}
			if len(public) == 3 {
				if _, err := tls.X509KeyPair(public[contracts.OwnerPublicTLSCertificate], public[contracts.OwnerPublicTLSKey]); err != nil {
					return mounts.ErrUnavailable
				}
				expected[contracts.OwnerPublicTLSCertificate], expected[contracts.OwnerPublicTLSKey] = true, true
			}
		}
	} else if phase != 1 {
		return mounts.ErrUnavailable
	}
	for key := range expected {
		if len(data[key]) == 0 {
			return mounts.ErrUnavailable
		}
	}
	actual := maps.Clone(data)
	delete(actual, contracts.InstallerInboxInspectionToken)
	if len(actual) != len(expected) {
		return mounts.ErrUnavailable
	}
	for key := range actual {
		if !expected[key] {
			return mounts.ErrUnavailable
		}
	}
	return nil
}

// One reader describes the private input groups for both ordinary CLI answers
// and mixed handoffs. Provider requests remain interpreted and verified by the
// existing provider adapters, not by this material-shape projection.
type installerProviderMaterialPlan struct {
	Federation json.RawMessage                   `json:"federation"`
	Publisher  json.RawMessage                   `json:"publisher"`
	Public     bool                              `json:"public"`
	Downloads  json.RawMessage                   `json:"downloadEvidenceReadStorage"`
	Cleanup    json.RawMessage                   `json:"operationCleanupStorage"`
	Deletion   json.RawMessage                   `json:"evidenceDeleteStorage"`
	ServingTLS contracts.InstallerServingTLSPlan `json:"servingTLS"`
}

func readInstallerProviderMaterialPlan(raw []byte) (installerProviderMaterialPlan, error) {
	var p installerProviderMaterialPlan
	if json.Unmarshal(raw, &p) != nil {
		return p, mounts.ErrUnavailable
	}
	return p, nil
}
