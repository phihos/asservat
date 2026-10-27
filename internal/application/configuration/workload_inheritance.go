package configuration

import (
	"maps"
	"slices"

	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// WorkloadSelectionOf is the connector journal selection a workloadMetadata
// source reads: its workload selector, and as keys the selector labels and
// the mapping key.
func WorkloadSelectionOf(s value.Source) value.WorkloadSelection {
	out := value.WorkloadSelection{Selector: maps.Clone(s.WorkloadSelector)}
	out.Keys.Labels = slices.Collect(maps.Keys(s.WorkloadSelector))
	switch s.Mapping.Field {
	case "label":
		out.Keys.Labels = append(out.Keys.Labels, s.Mapping.Key)
	case "annotation":
		out.Keys.Annotations = []string{s.Mapping.Key}
	}
	slices.Sort(out.Keys.Labels)
	out.Keys.Labels = slices.Compact(out.Keys.Labels)
	return out
}

// WorkloadGrantsWith evaluates a workloadMetadata source (REQ-PER-005,
// ADR-247) against its connector workload journal: the same fixed role,
// issuer and value mapping as namespaceMetadata, over one Deployment or
// StatefulSet each. It requires admissionEnforced protection and a current
// proof that the workload guard named by guardRef protects the selector and
// mapping keys against creation and mutation by other writers. Scope is the
// workload selector and excludedNamespaces; a namespaceSelector is not
// supported for workload sources. Pods are derived only at request time,
// through the validated controller chain of target resolution, never from
// pod labels.
func WorkloadGrantsWith(s value.Source, o *value.WorkloadObservation, ev value.SourceEvidence) ([]value.WorkloadGrant, string) {
	if !s.Enabled || s.Resource.Deleting {
		return nil, value.SourceDisabled
	}
	m := s.Mapping
	if s.Type != "workloadMetadata" || m.Mode != "valueMap" && m.Mode != "groupID" || m.Field != "label" && m.Field != "annotation" || s.Protection.Mode != "admissionEnforced" ||
		!identity.Text(s.Protection.ReviewRef, 256) || !identity.Text(s.Protection.GuardRef, 256) || !authorization.UUID(s.ClusterID) || !validRole(s.Role) || !identity.Text(m.Issuer, 2048) ||
		s.MaxNamespaces < 1 || s.MaxNamespaces > 1000 || m.Mode == "valueMap" && (len(m.Values) == 0 || len(m.Values) > 128) || m.Mode == "groupID" && len(m.Values) != 0 ||
		len(s.NamespaceSelector) != 0 || !WorkloadSelectionOf(s).Valid() {
		return nil, value.SourceUnsupported
	}
	sel := WorkloadSelectionOf(s)
	if o == nil {
		return nil, value.MetadataUnavailable
	}
	if o.ClusterID != s.ClusterID || !o.Selection.Equal(sel) {
		return nil, value.MetadataNotObserved
	}
	if reason := guardCovers(ev.WorkloadGuard, s.Protection.GuardRef, s.ClusterID, sel.Keys, ev.Now); reason != "" {
		return nil, reason
	}
	groups, reason := mappingGroups(m, ev)
	if reason != "" {
		return nil, reason
	}
	var out []value.WorkloadGrant
	for _, w := range o.Workloads {
		if w.Deleting || slices.Contains(s.ExcludedNamespaces, w.Namespace.Name) {
			continue
		}
		matched := true
		for k, v := range s.WorkloadSelector {
			if d := ValueDigest(v); d == "" || w.Labels[k] != d {
				matched = false
				break
			}
		}
		values := w.Annotations
		if m.Field == "label" {
			values = w.Labels
		}
		v, ok := values[m.Key]
		if !matched || !ok || v == "" || len(groups[v]) == 0 {
			continue
		}
		out = append(out, value.WorkloadGrant{Namespace: w.Namespace, Workload: w.Ref(), ResourceVersion: w.ResourceVersion, Subjects: slices.Clone(groups[v])})
	}
	if len(out) > s.MaxNamespaces {
		return nil, value.SourceTooManyNamespaces
	}
	return out, ""
}

// WorkloadBasis is the accepted basis of one workload grant: the source and
// the workload's journal version are provenance; the scope is that workload.
func WorkloadBasis(s value.Source, g value.WorkloadGrant) value.PermissionBasis {
	b := value.PermissionBasis{Resource: s.Resource, Scope: value.Scope{ClusterID: s.ClusterID, Namespace: g.Namespace, Workloads: []value.WorkloadRef{g.Workload}}, Effect: "Allow", Subjects: slices.Clone(g.Subjects), Roles: []string{s.Role}, ObservationVersion: g.ResourceVersion}
	b.ScopeDigest = PermissionScopeDigest(b)
	return b
}
