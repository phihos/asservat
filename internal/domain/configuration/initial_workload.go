package configuration

import (
	"asservat.local/asservat/internal/domain/artifact"
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
