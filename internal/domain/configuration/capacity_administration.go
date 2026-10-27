package configuration

import (
	"slices"

	"asservat.local/asservat/internal/domain/identity"
)

// These plans are protected installation inputs. EvidenceBudgetPolicy authors,
// status writers and capture callers cannot choose administrator/probe identities.
type CapacityAdministration struct {
	Name             string
	ControlNamespace NamespaceRef
	Administrators   []KubernetesActor
	StatusUsers      []string
	ProbeAccount     NamespaceRef // ServiceAccount name and immutable UID in ControlNamespace.
}

func (p CapacityAdministration) Valid() bool {
	if !identity.Text(p.Name, 63) || !identity.Text(p.ControlNamespace.Name, 63) || !identity.Text(p.ControlNamespace.UID, 64) || !actorsValid(p.Administrators) || !identity.Strings(p.StatusUsers, 16, 256) || !identity.Text(p.ProbeAccount.Name, 63) || !identity.Text(p.ProbeAccount.UID, 64) {
		return false
	}
	probe := "system:serviceaccount:" + p.ControlNamespace.Name + ":" + p.ProbeAccount.Name
	for _, a := range p.Administrators {
		if a.Kind == "User" && a.Name == probe {
			return false
		}
	}
	for _, user := range p.StatusUsers {
		if user == probe {
			return false
		}
	}
	return true
}

// CapacityNamespaceAdministration protects only the exact selector keys used
// by accepted budget policies. Deletion does not erase retained capacity and a
// replacement namespace UID never inherits its predecessor's account.
type CapacityNamespaceAdministration struct {
	Name           string
	Administrators []KubernetesActor
	Keys           []string
	ProbeNamespace NamespaceRef
	ProbeAccount   NamespaceRef
}

func (p CapacityNamespaceAdministration) Valid() bool {
	if !identity.Text(p.Name, 63) || !actorsValid(p.Administrators) || !identity.Strings(p.Keys, 256, 253) || len(p.Keys) == 0 || !identity.Text(p.ProbeNamespace.Name, 63) || !identity.Text(p.ProbeNamespace.UID, 64) || !identity.Text(p.ProbeAccount.Name, 63) || !identity.Text(p.ProbeAccount.UID, 64) {
		return false
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	probe := "system:serviceaccount:" + p.ProbeNamespace.Name + ":" + p.ProbeAccount.Name
	for _, a := range p.Administrators {
		if a.Kind == "User" && a.Name == probe {
			return false
		}
	}
	return true
}

// WorkloadAdministration is the workload metadata guard (ADR-247): only
// Administrators may create Deployments/StatefulSets carrying these label or
// annotation keys or change their presence or values. Its probe account
// shares the namespace selector guard's empty probe namespace.
type WorkloadAdministration struct {
	Name                      string
	Administrators            []KubernetesActor
	LabelKeys, AnnotationKeys []string
	ProbeNamespace            NamespaceRef
	ProbeAccount              NamespaceRef
}

func (p WorkloadAdministration) Valid() bool {
	keys := NamespaceKeys{Labels: p.LabelKeys, Annotations: p.AnnotationKeys}
	if !keys.Valid() || len(p.LabelKeys)+len(p.AnnotationKeys) == 0 {
		return false
	}
	return CapacityNamespaceAdministration{Name: p.Name, Administrators: p.Administrators, Keys: append(slices.Clone(p.LabelKeys), p.AnnotationKeys...), ProbeNamespace: p.ProbeNamespace, ProbeAccount: p.ProbeAccount}.Valid()
}
