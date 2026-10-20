package kubernetes

import (
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"
)

// BuildProviderOwnerWorkload derives only the fresh v2 original template.
// The immutable identity projection contains the four SQL roles; renewable
// provider authentication and rotating audit storage have separate fixed
// projections. All existing v1 template/receipt bytes remain untouched.
func BuildProviderOwnerWorkload(p OwnerWorkloadPlan, clusterID string, selection contracts.OwnerProviderSelection) (*OwnerWorkload, error) {
	if !authorization.UUID(clusterID) || providerconfig.ValidateOwnerProviderSelection(p.InstallationID, selection) != nil {
		return nil, cfg.ErrInvalid
	}
	w, err := BuildInstalledOwnerWorkload(p)
	if err != nil {
		return nil, err
	}
	pod := &w.Deployment.Spec.Template.Spec
	projection := pod.Volumes[0].Projected
	keys := contracts.OwnerIdentityProjectionFiles()
	items := make([]core.KeyToPath, 0, len(keys))
	for _, key := range keys {
		items = append(items, core.KeyToPath{Key: key, Path: key})
	}
	projection.Sources[1].Secret.Items = items
	projection.Sources = append(projection.Sources,
		core.VolumeProjection{Secret: &core.SecretProjection{
			LocalObjectReference: core.LocalObjectReference{Name: selection.AuditCredentials.Name},
			Items:                []core.KeyToPath{{Key: contracts.OwnerProviderAuditCredentialFile, Path: contracts.OwnerProviderAuditCredentialFile}},
		}},
		core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{
			Path: contracts.OwnerProviderTokenFile, Audience: contracts.OwnerProviderAudience(p.InstallationID, clusterID), ExpirationSeconds: ptr.To(int64(600)),
		}},
	)
	// ADR-204: the hub-local download worker API's client and guard probe
	// tokens join the backend (observation) root. This template is pinned
	// before the worker namespace exists, so the files are named by cluster
	// and fixed namespace name; both are the owner account's own default-
	// audience tokens, as kube-observer.token is, and confer only the rights
	// the downloads step later binds in that namespace.
	observation := -1
	for i, v := range pod.Volumes {
		if v.Name == "observation" && v.Secret != nil {
			observation = i
		}
	}
	if observation < 0 {
		return nil, cfg.ErrInvalid
	}
	workers := contracts.DownloadWorkerNamespaceName(p.InstallationID)
	pod.Volumes[observation].VolumeSource = core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: ptr.To(int32(0440)), Sources: []core.VolumeProjection{
		{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: contracts.OwnerObservationProjectionName(p.InstallationID)}, Optional: ptr.To(true)}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.NativeKubernetesTokenFile(clusterID, workers), ExpirationSeconds: ptr.To(int64(600))}},
		{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.NativeKubernetesProbeTokenFile(clusterID, workers), ExpirationSeconds: ptr.To(int64(600))}},
	}}}
	w.Role.Rules = append(w.Role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{selection.AuditCredentials.Name}, Verbs: []string{"get"}})
	// ADR-185: the promoted hub-api reads its settings and proves each guarded
	// public source's own denial with a dry-run UPDATE, so it holds update on
	// exactly those sources and get on their guards.
	sources := contracts.OwnerPublicGuardedSources(p.InstallationID)
	guards := make([]string, 0, len(sources)+1)
	for _, name := range sources {
		guards = append(guards, name+"-guard")
	}
	// ADR-210: the capacity processing source, whose guard is named by
	// capacity, for the operator's processing decisions.
	_, _, _, processingSource, processingGuard := CapacitySourceNames(p.InstallationID)
	sources, guards = append(sources, processingSource), append(guards, processingGuard)
	w.Role.Rules = append(w.Role.Rules,
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: sources, Verbs: []string{"get", "update"}},
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: append([]string{contracts.OwnerBrowserSettingsName(p.InstallationID), contracts.OwnerIdentitySettingsName(p.InstallationID)}, contracts.OwnerClusterTopologyNames(p.InstallationID)...), Verbs: []string{"get"}})
	w.ClusterRole.Rules = append(w.ClusterRole.Rules, rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: guards, Verbs: []string{"get"}})
	// ADR-190 decision 7: the hub cluster's capacity observation reads
	// namespace and workload metadata cluster-wide and the selector guard.
	// The probe account's token and object rights are a Role in the probe
	// namespace, which the capacity step creates later.
	_, selector, _, _, _ := CapacitySourceNames(p.InstallationID)
	w.ClusterRole.Rules = append(w.ClusterRole.Rules,
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces", "pods"}, Verbs: []string{"get", "list"}},
		rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
		rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{selector}, Verbs: []string{"get"}})
	return w, nil
}
