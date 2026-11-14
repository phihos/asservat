package configuration

// InitialNamespaceAdministration describes an inert policy that can be
// installed before a fresh namespace exists. It carries no invented namespace
// UID and is not proof of installation history or activation authority.
type InitialNamespaceAdministration struct {
	Name, Namespace, ProbeSource, Inputs string
	Administrators                       []KubernetesActor
}
