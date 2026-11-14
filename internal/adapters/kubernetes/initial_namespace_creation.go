package kubernetes

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	"k8s.io/client-go/rest"
)

// InitialNamespaceResources is creation provenance, not clean-history proof or
// activation authority. On failure, retain any nonempty references before retry.
type InitialNamespaceResources struct {
	Namespace cfg.NamespaceRef
	Guard     GuardPin
}

type InitialNamespaceCreator struct {
	api                   rest.Interface
	plan                  cfg.InitialNamespaceAdministration
	installation, request string
	policy                *admission.ValidatingAdmissionPolicy
	binding               *admission.ValidatingAdmissionPolicyBinding
}
