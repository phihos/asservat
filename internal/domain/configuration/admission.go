package configuration

import (
	"asservat.local/asservat/internal/domain/identity"
)

// KubernetesActor refers to the API server's authenticated username/group, not
// an OIDC evidence subject or a client-provided AdmissionReview field.
type KubernetesActor struct{ Kind, Name string }

// PermissionAdministration is trusted installation configuration. It is not
// writable by AccessBinding/PermissionSource authors. Changes require a newly
// qualified guard revision and fence the previous accepted stream.
type PermissionAdministration struct {
	Name             string
	ControlNamespace NamespaceRef
	Administrators   []KubernetesActor
	StatusUsers      []string
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
	if !identity.Text(p.Name, 63) || !identity.Text(p.ControlNamespace.Name, 63) || !identity.Text(p.ControlNamespace.UID, 64) || !actorsValid(p.Administrators) || !identity.Strings(p.StatusUsers, 16, 256) || len(p.StatusUsers) == 0 {
		return false
	}
	return true
}
