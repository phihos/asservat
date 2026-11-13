package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Helm-native permission child sources (helm-native-install plan). Kubernetes
// RBAC protects the control namespace's PermissionSources, AccessBindings,
// retention policies and the worker profile ConfigMap; these readers only
// confirm the namespace is current and carry the deterministic digest that
// SQL persists. No admission policy, pin or dry-run proof is involved.

// NewPlainPermissionTrust is the permission stream's trust reader with a
// caller-computed deterministic digest of the installed permission
// configuration.
func NewPlainPermissionTrust(observer *PermissionClient, digest artifact.Digest) (*PermissionGuard, error) {
	if observer == nil || digest == (artifact.Digest{}) {
		return nil, value.ErrInvalid
	}
	return &PermissionGuard{observer: observer, plan: value.PermissionAdministration{ControlNamespace: observer.control}, digest: digest}, nil
}

// NewPlainRetentionSource is the hub retention source protection reader of
// the observer's namespace with the deterministic
// contracts.RetentionSourceDigest.
func NewPlainRetentionSource(observer *PermissionClient) (*RetentionGuard, error) {
	if observer == nil {
		return nil, value.ErrInvalid
	}
	digest := artifact.Digest(contracts.RetentionSourceDigest(observer.clusterID, observer.control.Name))
	return &RetentionGuard{observer: observer, plan: value.RetentionAdministration{ControlNamespace: observer.control}, digest: digest}, nil
}

// NewPlainWorkerConfigurationProtection names the worker profile ConfigMap in
// the observer's namespace with the deterministic
// contracts.ConfigMapSourceDigest, which the hub-api computes the same way.
func NewPlainWorkerConfigurationProtection(observer *PermissionClient, source string) (*WorkerConfigurationProtection, error) {
	if observer == nil || len(validation.IsDNS1123Subdomain(source)) != 0 {
		return nil, value.ErrInvalid
	}
	digest := artifact.Digest(contracts.ConfigMapSourceDigest(observer.clusterID, observer.control.Name, source))
	return &WorkerConfigurationProtection{&configMapProtection{observer: observer, plan: value.ConfigMapAdministration{SourceName: source, ControlNamespace: observer.control}, digest: digest}}, nil
}
