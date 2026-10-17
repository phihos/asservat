package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"
)

// BuildProviderHubWorkerWorkload is selected only by the joint fresh v2
// resource constructor. It retains the v1 builder's bytes and authority graph;
// this separate template has no mounted legacy provider tokens.
func BuildProviderHubWorkerWorkload(p HubWorkerWorkloadPlan, installationID, clusterID string, selection contracts.ConfigurationProviderSelection) (*HubWorkerWorkload, error) {
	if !authorization.UUID(clusterID) || providerconfig.ValidateConfigurationProviderSelection(installationID, selection) != nil || p.Credentials != selection.AuditCredentials.Name {
		return nil, cfg.ErrInvalid
	}
	w, err := BuildInstalledHubWorkerWorkload(p, installationID)
	if err != nil {
		return nil, err
	}
	// Match the actual Deployment, ReplicaSet and Pod without adopting
	// admission-injected eviction bounds as new installation input.
	w.Deployment.Spec.Template.Spec.Tolerations = []core.Toleration{
		{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))},
		{Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))},
	}
	// Fixed position and shape are owned by the unmodified builder, never
	// caller-supplied Pod JSON. SQL credentials remain in their separate Secret.
	sources := w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources
	if len(sources) < 2 || sources[1].Secret == nil || sources[1].Secret.Name != selection.AuditCredentials.Name {
		return nil, cfg.ErrInvalid
	}
	sources[1].Secret.Items = []core.KeyToPath{{Key: contracts.ConfigurationProviderAuditCredentialFile, Path: contracts.ConfigurationProviderAuditCredentialFile}}
	w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources = append(sources,
		core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{
			Path: contracts.ConfigurationProviderTokenFile, Audience: contracts.ConfigurationProviderAudience(installationID, clusterID), ExpirationSeconds: ptr.To(int64(600)),
		}})
	// This permits the entire selected Secret payload. The protected producer
	// must establish its one-purpose/one-key construction and original UID.
	// Current runtime validation compares those exact bytes with the mount.
	w.Role.Rules = append(w.Role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{p.Configuration}, Verbs: []string{"get"}}, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{selection.AuditCredentials.Name}, Verbs: []string{"get"}})
	// This immutable four-key object is already fully mounted. Its original
	// UID and bytes are rechecked before provider login; no private role journal
	// or unrelated Secret can be selected. This grant exists only in fresh v2.
	sql := "asservat-configuration-runtime-" + strings.ReplaceAll(installationID, "-", "")
	w.Role.Rules = append(w.Role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{sql}, Verbs: []string{"get"}})
	return w, nil
}
