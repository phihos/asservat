package capture

import (
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/targets"
	"time"
)

func policyObservedCatalogTarget(o targets.RestartObservation) targets.Request {
	return targets.Request{ClusterID: o.ClusterID, Namespace: o.Namespace, Workload: o.Workload}
}

// Accepted workload identity scopes catalog lookup without selecting a Pod.
// Source names are checked again against the canonical accepted scope; a
// namespace replacement is refused by the existing regional catalog reader.
func policyAcceptedCatalogTarget(spec []byte, a authorization.AcceptedPolicyAuthority) (targets.Request, error) {
	p, _, err := policyObservationPlan(spec)
	if err != nil {
		return targets.Request{}, err
	}
	if p.ClusterID != a.ClusterID || a.NamespaceUID == "" || a.WorkloadUID == "" {
		return targets.Request{}, value.ErrChanged
	}
	return targets.Request{ClusterID: a.ClusterID, Namespace: configuration.NamespaceRef{Name: p.Namespace, UID: a.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: p.WorkloadKind, Name: p.WorkloadName, UID: a.WorkloadUID}}, nil
}

func minPolicyDeadline(first time.Time, rest ...time.Time) time.Time {
	for _, end := range rest {
		if end.Before(first) {
			first = end
		}
	}
	return first
}
