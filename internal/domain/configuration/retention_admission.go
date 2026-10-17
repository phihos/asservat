package configuration

import (
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type RetentionDelegation struct {
	Writers []KubernetesActor
	Scope   privacy.PolicyScope
}
type RetentionAdministration struct {
	Name             string
	ControlNamespace NamespaceRef
	Administrators   []KubernetesActor
	StatusUsers      []string
	Delegations      []RetentionDelegation
}

func (p RetentionAdministration) Valid() bool {
	if !identity.Text(p.Name, 63) || !identity.Text(p.ControlNamespace.Name, 63) || !identity.Text(p.ControlNamespace.UID, 64) || !actorsValid(p.Administrators) || !identity.Strings(p.StatusUsers, 16, 256) || len(p.StatusUsers) == 0 || len(p.Delegations) > 32 {
		return false
	}
	for _, d := range p.Delegations {
		if !actorsValid(d.Writers) || !d.Scope.Valid() || d.Scope.Empty() {
			return false
		}
	}
	return true
}
