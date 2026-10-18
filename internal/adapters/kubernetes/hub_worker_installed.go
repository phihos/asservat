package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	"k8s.io/utils/ptr"
)

// BuildInstalledHubWorkerWorkload is the fixed configuration-first installed
// profile. Both later credential projections are optional only for Pod startup;
// runtime must independently verify their original positive journal receipts.
// The qualified configuration-only builder keeps its original bytes.
func BuildInstalledHubWorkerWorkload(p HubWorkerWorkloadPlan, installationID string) (*HubWorkerWorkload, error) {
	if !authorization.UUID(installationID) {
		return nil, cfg.ErrInvalid
	}
	names := runtimeResourceNames(installationID)
	if p.Name != names.Worker || p.ServiceAccount != names.Worker || p.Configuration != names.WorkerInputs || p.Credentials != names.WorkerProviders || p.OwnerSource != names.OwnerSource || p.OwnerGuard != names.OwnerSourceGuard || p.LeaderLease != names.Lease {
		return nil, cfg.ErrInvalid
	}
	w, err := BuildProvisionedHubWorkerWorkload(p, installationID)
	if err != nil {
		return nil, err
	}
	add := func(secret, directory string, keys []string) {
		items := make([]core.KeyToPath, 0, len(keys))
		for _, key := range keys {
			items = append(items, core.KeyToPath{Key: key, Path: directory + "/" + key})
		}
		w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources = append(w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources,
			core.VolumeProjection{Secret: &core.SecretProjection{LocalObjectReference: core.LocalObjectReference{Name: secret}, Items: items, Optional: ptr.To(true)}})
	}
	add(contracts.CapacityRuntimeProjectionName(installationID), contracts.CapacityWorkerProjectionDirectory, []string{
		contracts.CapacityDeploymentFile, contracts.CapacityCredentialManifestFile, contracts.CaptureAccountKeyFile,
		"sql-capacity.json", "sql-capacity-capture.json",
	})
	add(contracts.HubWorkerCleanupProjectionName(installationID), contracts.HubWorkerCleanupProjectionDirectory, []string{
		contracts.HubWorkerCleanupDeploymentFile, contracts.HubWorkerCleanupManifestFile,
		"sql-capture-cleanup.json", "sql-capture-verifier.json", "sql-capture-finalizer.json",
		"cleanup-storage.json", "verify-storage.json",
		"certificate-wrap.token", "certificate-open.token", "certificate-verify.token", "certificate-sign.token",
	})
	add(contracts.PermissionRuntimeProjectionName(installationID), contracts.PermissionWorkerProjectionDirectory, []string{
		contracts.PermissionDeploymentFile, contracts.PermissionCredentialManifestFile,
		"sql-permission-accept.json", "sql-permission-audit.json",
		// ADR-195: the hub retention source logins ride in this projection.
		"sql-retention-source.json", "sql-retention-source-audit.json", "sql-retention-catchup.json", "sql-retention-lifecycle-audit.json",
		// ADR-204: the worker configuration acceptance logins, present only
		// with the projection's worker configuration section.
		"sql-worker-config-observe.json", "sql-worker-config-audit.json",
		// ADR-205: the context deletion logins, present only with the
		// projection's context deletion section.
		"sql-context-cleanup.json", "sql-context-cleanup-audit.json", "sql-context-cleanup-finalize.json",
	})
	// ADR-205 decision 4: the operator's evidence delete credential, in its
	// own immutable Secret; absent without a context deletion section.
	add(contracts.EvidenceDeleteCredentialName(installationID), contracts.EvidenceDeleteDirectory, []string{contracts.EvidenceDeleteCredentialFile})
	// Only this Pod's rotating token is projected. It has the fixed local-hop
	// audience and carries no remote Kubernetes credential. The UID hint is
	// independently checked by the actual receiver's online TokenReview.
	w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources = append(w.Deployment.Spec.Template.Spec.Volumes[0].Projected.Sources,
		core.VolumeProjection{ServiceAccountToken: &core.ServiceAccountTokenProjection{Path: contracts.HubWorkerClusterObservationTokenFile, Audience: fleet.ClusterObservationAudience(installationID), ExpirationSeconds: ptr.To(int64(600))}})
	w.Deployment.Spec.Template.Spec.Containers[0].Env = []core.EnvVar{{Name: contracts.OwnerPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}}
	// The resource journal has only public original CREATE/activation provenance.
	// No private role journal, arbitrary Secret, SQL admin or token-mint grant is
	// added. The fixed runtime reader still pins actual UIDs and current guards.
	w.Role.Rules = append(w.Role.Rules,
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"asservat-runtime-resources-" + strings.ReplaceAll(installationID, "-", ""), contracts.CapacityRuntimeProjectionName(installationID), contracts.HubWorkerCleanupProjectionName(installationID), contracts.PermissionRuntimeProjectionName(installationID)}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, ResourceNames: []string{names.Worker}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{names.Worker}, Verbs: []string{"get"}},
		// The existing native workload guard independently rejects this exact
		// dry-run UPDATE. RBAC denial alone is never enforcement evidence; the
		// same guard denies every persistent worker-origin Deployment edit.
		rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{names.Owner}, Verbs: []string{"get", "update"}},
	)
	w.ClusterRole.Rules[1].ResourceNames = append(w.ClusterRole.Rules[1].ResourceNames, names.WorkloadGuard)
	augmentInstalledWorkerOwnerReads(w, installationID)
	augmentInstalledWorkerCapacityReads(w, installationID)
	augmentInstalledWorkerPermissionReads(w, installationID)
	return w, nil
}
