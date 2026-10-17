package kubernetes

import rbac "k8s.io/api/rbac/v1"

// augmentInstalledWorkerOwnerReads is called only by the fresh installed
// builder, before its original workload/RBAC claims. It supplies local public
// metadata needed to independently authenticate the actual observation server
// before revealing this Pod's dedicated token. No remote credential, Secret
// permission or mutation is introduced. Readers retain exact UIDs and bounded
// selector-filtered EndpointSlice pages; RBAC does not supply those proofs.
func augmentInstalledWorkerOwnerReads(w *HubWorkerWorkload, installationID string) {
	names := runtimeResourceNames(installationID)
	w.Role.Rules = append(w.Role.Rules,
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"services", "serviceaccounts"}, ResourceNames: []string{names.Owner}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get"}},
		rbac.PolicyRule{APIGroups: []string{"discovery.k8s.io"}, Resources: []string{"endpointslices"}, Verbs: []string{"list"}},
	)
}
