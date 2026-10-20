package kubernetes

import (
	"strings"

	"asservat.local/asservat/internal/contracts"
	rbac "k8s.io/api/rbac/v1"
)

// This fixed read/probe graph belongs only to the fresh installed worker's
// original Role/ClusterRole templates. RBAC cannot distinguish a dry-run CREATE
// or UPDATE: the exact original namespace branch and independently pinned
// capacity/processing source guards must enforce those denials. Their absence
// never becomes a usable current observation. There is no remote API access,
// Secret privilege or namespace-wide ConfigMap read. Capacity UPDATE, DELETE and
// status subresources are absent from this role.
func augmentInstalledWorkerCapacityReads(w *HubWorkerWorkload, installationID string) {
	prefix := "asservat-" + strings.ReplaceAll(installationID, "-", "")
	w.Role.Rules = append(w.Role.Rules,
		rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"evidencestoragepools", "evidencebudgetpolicies"}, Verbs: []string{"get", "list", "create"}},
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{prefix + "-processing-source"}, Verbs: []string{"get", "update"}},
	)
	w.ClusterRole.Rules = append(w.ClusterRole.Rules,
		rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{prefix + "-capacity-guard", prefix + "-processing-guard"}, Verbs: []string{"get"}},
	)
}

// ADR-189: the permission stream reader lists and watches the control
// namespace's AccessBindings and PermissionSources and reads each binding's
// scope namespace. The CREATE verb exists only for the guard's dry-run probe:
// the namespace guard admits nothing else from this account, and the
// permission guard must deny the probe itself.
func augmentInstalledWorkerPermissionReads(w *HubWorkerWorkload, installationID string) {
	w.Role.Rules = append(w.Role.Rules,
		rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings", "permissionsources"}, Verbs: []string{"get", "list", "watch"}},
		rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"accessbindings"}, Verbs: []string{"create"}},
		// ADR-195: the hub retention source reader and its guard's probe.
		rbac.PolicyRule{APIGroups: []string{"asservat.io"}, Resources: []string{"evidenceretentionpolicies"}, Verbs: []string{"get", "list", "watch", "create"}},
		// ADR-210: the browser settings, read by name for their SQL projection.
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{contracts.OwnerBrowserSettingsName(installationID)}, Verbs: []string{"get"}},
	)
	w.ClusterRole.Rules = append(w.ClusterRole.Rules,
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{contracts.PermissionGuardName(installationID), contracts.RetentionGuardName(installationID)}, Verbs: []string{"get"}},
	)
}
