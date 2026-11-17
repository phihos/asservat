package privacy

import (
	"slices"
	"strings"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyScope selects clusters and, by labels, namespaces and workloads.
type PolicyScope struct {
	ClusterIDs                      []string
	NamespaceLabels, WorkloadLabels map[string]string
}

// ScopedPolicy is one EvidenceRetentionPolicy of the hub control namespace.
// An empty scope is the installation baseline.
type ScopedPolicy struct {
	Name                                     string
	Policy                                   Policy
	Scope                                    PolicyScope
	CaseDefaultSeconds, CaseMaximumSeconds   int64
	AuditDefaultSeconds, AuditMaximumSeconds int64
	LegalExceptions                          string
	// Rejected names why the hub worker could not accept the object
	// (RejectedSpec: schema; RejectedPolicy: domain rules). A rejected
	// policy changes no stored deadline and refuses new collection in its
	// cluster scope, which is every cluster when the scope is unreadable.
	Rejected string `json:",omitempty"`
}

const (
	RejectedSpec   = "RejectedSpec"
	RejectedPolicy = "RejectedPolicy"
)

func (s PolicyScope) Empty() bool {
	return len(s.ClusterIDs) == 0 && len(s.NamespaceLabels) == 0 && len(s.WorkloadLabels) == 0
}

// Labeled reports a namespace or workload label selector.
func (s PolicyScope) Labeled() bool { return len(s.NamespaceLabels) > 0 || len(s.WorkloadLabels) > 0 }

func (s PolicyScope) Valid() bool {
	for _, id := range s.ClusterIDs {
		if !authorization.UUID(id) {
			return false
		}
	}
	for _, labels := range []map[string]string{s.NamespaceLabels, s.WorkloadLabels} {
		for k, v := range labels {
			if !identity.Text(k, 253) || !identity.Text(v, 63) {
				return false
			}
		}
	}
	return true
}

// TargetLabels are the namespace and workload labels read with a target's
// resolution. The workload is the Deployment or StatefulSet, or the Pod
// itself for a bare Pod. nil means the labels were not observed.
type TargetLabels struct {
	Namespace map[string]string `json:"namespace,omitempty"`
	Workload  map[string]string `json:"workload,omitempty"`
}

// EncodeLabels is the canonical text of l ("" for nil): sorted
// "n:key=value" and "w:key=value" entries joined by ",". Kubernetes label
// keys and values cannot contain "=" or ",", so the text is unambiguous.
func EncodeLabels(l *TargetLabels) string {
	if l == nil {
		return ""
	}
	entries := []string{"labels"}
	for prefix, labels := range map[string]map[string]string{"n:": l.Namespace, "w:": l.Workload} {
		for k, v := range labels {
			entries = append(entries, prefix+k+"="+v)
		}
	}
	slices.Sort(entries)
	return strings.Join(entries, ",")
}

// DecodeLabels reverses EncodeLabels; text it cannot read is nil (labels
// not observed), which refuses collection under a covering labeled policy.
func DecodeLabels(text string) *TargetLabels {
	entries := strings.Split(text, ",")
	if !slices.Contains(entries, "labels") {
		return nil
	}
	out := &TargetLabels{}
	for _, e := range entries {
		if e == "labels" {
			continue
		}
		k, v, ok := strings.Cut(e[min(2, len(e)):], "=")
		var into *map[string]string
		switch {
		case strings.HasPrefix(e, "n:"):
			into = &out.Namespace
		case strings.HasPrefix(e, "w:"):
			into = &out.Workload
		}
		if !ok || into == nil || k == "" {
			return nil
		}
		if *into == nil {
			*into = map[string]string{}
		}
		(*into)[k] = v
	}
	return out
}

// Selects applies matchLabels semantics: every selector key must be present
// with its value. An unlabeled scope selects every target.
func (s PolicyScope) Selects(l TargetLabels) bool {
	return subset(s.NamespaceLabels, l.Namespace) && subset(s.WorkloadLabels, l.Workload)
}

func subset(selector, labels map[string]string) bool {
	for k, v := range selector {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// Covers reports whether the policy's cluster scope includes cluster.
func (s PolicyScope) Covers(cluster string) bool {
	return len(s.ClusterIDs) == 0 || slices.Contains(s.ClusterIDs, cluster)
}

func (p ScopedPolicy) Valid() bool {
	if p.Rejected != "" {
		return identity.Text(p.Name, 253) && p.Policy.Revision.Valid() && p.Scope.Valid() && !p.Policy.Baseline && (p.Rejected == RejectedSpec || p.Rejected == RejectedPolicy)
	}
	return identity.Text(p.Name, 253) && p.Policy.Valid() && p.Scope.Valid() && p.Policy.Baseline == p.Scope.Empty() && age(p.CaseDefaultSeconds) && age(p.CaseMaximumSeconds) && age(p.AuditDefaultSeconds) && age(p.AuditMaximumSeconds) && (p.LegalExceptions == "disabled" || p.LegalExceptions == "reviewed")
}

// MatchPolicies selects the policies of the current set that apply to the
// target: every policy whose cluster scope covers it and whose label
// selectors match labels. A covering labeled policy refuses new collection
// when labels is nil (not observed), as does a covering rejected policy (it
// may be stricter than the others). Exactly one baseline is required.
// revision identifies the matched set; the caller digests it.
func MatchPolicies(policies []ScopedPolicy, t authorization.Target, labels *TargetLabels, revision func([]Policy) identity.Revision) (PolicySet, error) {
	out := PolicySet{Target: t}
	if !t.Valid() {
		return out, ErrInvalid
	}
	baselines := 0
	seen := map[string]bool{}
	for _, p := range policies {
		if !p.Valid() || seen[p.Policy.Revision.UID] {
			return out, ErrUnavailable
		}
		seen[p.Policy.Revision.UID] = true
		if !p.Scope.Covers(t.ClusterID) {
			continue
		}
		if p.Rejected != "" || p.Scope.Labeled() && labels == nil {
			return out, ErrUnavailable
		}
		if p.Scope.Labeled() && !p.Scope.Selects(*labels) {
			continue
		}
		if p.Policy.Baseline {
			baselines++
		}
		out.Policies = append(out.Policies, clonePolicy(p.Policy))
	}
	if baselines != 1 {
		return out, ErrUnavailable
	}
	slices.SortFunc(out.Policies, func(a, b Policy) int { return strings.Compare(a.Revision.UID, b.Revision.UID) })
	out.Revision = revision(out.Policies)
	return out, nil
}

func clonePolicy(p Policy) Policy {
	p.Rules = slices.Clone(p.Rules)
	for i := range p.Rules {
		p.Rules[i].PrivacyClasses = slices.Clone(p.Rules[i].PrivacyClasses)
		p.Rules[i].EvidenceTypes = slices.Clone(p.Rules[i].EvidenceTypes)
	}
	return p
}

// EvidenceMaximum is the policy's maximum age for evidence of the given type
// collected as potential user data, the class every collector records.
func (p Policy) EvidenceMaximum(evidenceType string) int64 {
	maximum := p.MaximumSeconds
	for _, r := range p.Rules {
		if matchesClass(r.PrivacyClasses, "potentialPersonalData") && (len(r.EvidenceTypes) == 0 || evidenceType == "other" || slices.Contains(r.EvidenceTypes, evidenceType)) {
			maximum = min(maximum, r.MaxAgeSeconds)
		}
	}
	return maximum
}
