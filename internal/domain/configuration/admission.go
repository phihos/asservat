package configuration

import (
	"slices"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// KubernetesActor refers to the API server's authenticated username/group, not
// an OIDC evidence subject or a client-provided AdmissionReview field.
type KubernetesActor struct{ Kind, Name string }
type PermissionDelegation struct {
	Writers        []KubernetesActor
	Scope          Scope
	Roles, Issuers []string
}

// PermissionAdministration is trusted installation configuration. It is not
// writable by AccessBinding/PermissionSource authors. Changes require a newly
// qualified guard revision and fence the previous accepted stream.
type PermissionAdministration struct {
	Name             string
	ControlNamespace NamespaceRef
	Administrators   []KubernetesActor
	StatusUsers      []string
	Delegations      []PermissionDelegation
}

func actorsValid(v []KubernetesActor) bool {
	if len(v) < 1 || len(v) > 32 {
		return false
	}
	seen := map[KubernetesActor]bool{}
	for _, a := range v {
		if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) || seen[a] {
			return false
		}
		seen[a] = true
	}
	return true
}
func (p PermissionAdministration) Valid() bool {
	if !identity.Text(p.Name, 63) || !identity.Text(p.ControlNamespace.Name, 63) || !identity.Text(p.ControlNamespace.UID, 64) || !actorsValid(p.Administrators) || !identity.Strings(p.StatusUsers, 16, 256) || len(p.StatusUsers) == 0 || len(p.Delegations) > 64 {
		return false
	}
	for _, d := range p.Delegations {
		if !actorsValid(d.Writers) || !authorization.UUID(d.Scope.ClusterID) || !identity.Text(d.Scope.Namespace.Name, 63) || !identity.Text(d.Scope.Namespace.UID, 64) || !identity.Strings(d.Roles, 4, 32) || len(d.Roles) == 0 || !identity.Strings(d.Issuers, 8, 2048) || len(d.Issuers) == 0 || len(d.Scope.Workloads) > 64 {
			return false
		}
		for _, role := range d.Roles {
			if !slices.Contains([]string{"workload-maintainer", "evidence-reader", "evidence-owner", "action-approver"}, role) {
				return false
			}
		}
		seen := map[string]bool{}
		for _, w := range d.Scope.Workloads {
			if !identity.Text(w.Name, 253) || !identity.Text(w.UID, 64) || (w.Kind != "Deployment" && w.Kind != "StatefulSet") || seen[w.UID] {
				return false
			}
			seen[w.UID] = true
		}
	}
	return true
}
