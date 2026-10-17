package configuration

import "asservat.local/asservat/internal/domain/identity"

// ConfigMapAdministration names one protected installation ConfigMap.
// It carries no application/evidence permission.
type ConfigMapAdministration struct {
	Name, SourceName string
	ControlNamespace NamespaceRef
	Administrators   []KubernetesActor
}

func (p ConfigMapAdministration) Valid() bool {
	return identity.Text(p.Name, 253) && identity.Text(p.SourceName, 253) && identity.Text(p.ControlNamespace.Name, 63) && identity.Text(p.ControlNamespace.UID, 64) && actorsValid(p.Administrators)
}

// Retain the existing worker configuration contract and constructor type.
type WorkerAdministration = ConfigMapAdministration
