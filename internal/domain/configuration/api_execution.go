package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// APIExecutionAdministration is installation-owned, not a capture or remote
// caller input. Current guard enforcement does not prove historical cleanliness.
type APIExecutionAdministration struct {
	Name                                   string
	ControlNamespace                       NamespaceRef
	InstallationID, ClusterID, IssuerEpoch string
	PodName, PodUID, Account, AccountUID   string
	CapacityAccount, CapacityAccountUID    string
	ProbeAccount, ProbeAccountUID          string
	PodSpecDigest, ImageDigest             artifact.Digest
	Administrators                         []KubernetesActor
}

func (p APIExecutionAdministration) Valid() bool {
	for _, id := range []string{p.InstallationID, p.ClusterID, p.IssuerEpoch, p.ControlNamespace.UID, p.PodUID, p.AccountUID, p.CapacityAccountUID, p.ProbeAccountUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, name := range []string{p.Name, p.PodName, p.Account, p.CapacityAccount, p.ProbeAccount} {
		if !identity.Text(name, 253) {
			return false
		}
	}
	if !identity.Text(p.ControlNamespace.Name, 63) || p.PodSpecDigest == (artifact.Digest{}) || p.ImageDigest == (artifact.Digest{}) || p.Account == p.CapacityAccount || p.Account == p.ProbeAccount || p.CapacityAccount == p.ProbeAccount || p.AccountUID == p.CapacityAccountUID || p.AccountUID == p.ProbeAccountUID || p.CapacityAccountUID == p.ProbeAccountUID || len(p.Administrators) < 1 || len(p.Administrators) > 32 {
		return false
	}
	for _, a := range p.Administrators {
		if (a.Kind != "User" && a.Kind != "Group") || !identity.Text(a.Name, 256) {
			return false
		}
	}
	return true
}
