package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// InitialWorkloadAdministration is private installation input for one finite
// Pod. It neither accepts recovery nor grants ongoing runtime administration.
type InitialWorkloadAdministration struct {
	Handover                                  bool `json:",omitempty"`
	Name, Configuration, Witness, FleetSource string
	ControlNamespace                          NamespaceRef
	PodName, PodUID                           string
	WriterAccount, WriterAccountUID           string
	ProbeAccount, ProbeAccountUID             string
	PodSpecDigest                             artifact.Digest
	Administrators                            []KubernetesActor
}

func (p InitialWorkloadAdministration) Valid() bool {
	for _, name := range []string{p.Name, p.Configuration, p.Witness, p.FleetSource, p.ControlNamespace.Name, p.PodName, p.WriterAccount, p.ProbeAccount} {
		if !identity.Text(name, 253) {
			return false
		}
	}
	return authorization.UUID(p.ControlNamespace.UID) && authorization.UUID(p.PodUID) && authorization.UUID(p.WriterAccountUID) && authorization.UUID(p.ProbeAccountUID) && p.PodSpecDigest != (artifact.Digest{}) && actorsValid(p.Administrators) && p.WriterAccount != p.ProbeAccount && p.WriterAccountUID != p.ProbeAccountUID && p.Configuration != p.Witness && p.Configuration != p.FleetSource && p.Witness != p.FleetSource
}
