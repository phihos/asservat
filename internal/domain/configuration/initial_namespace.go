package configuration

import "asservat.local/asservat/internal/domain/identity"

// InitialNamespaceAdministration describes an inert policy that can be
// installed before a fresh namespace exists. It carries no invented namespace
// UID and is not proof of installation history or activation authority.
type InitialNamespaceAdministration struct {
	Name, Namespace, ProbeSource, Inputs string
	Administrators                       []KubernetesActor
}

func (p InitialNamespaceAdministration) Valid() bool {
	return identity.Text(p.Name, 253) && identity.Text(p.Namespace, 63) && identity.Text(p.ProbeSource, 253) && identity.Text(p.Inputs, 253) && p.ProbeSource != p.Inputs && actorsValid(p.Administrators)
}
