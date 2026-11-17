package privacy

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Retention policy effects (ADR-330 D12, REQ-PRV-002). A policy event
// shortens the stored deadlines of the artifacts it matches; the impact
// preview (ADR-240) computes the same effect for a proposal and writes
// nothing. Deadlines only shorten, so a longer maximum or a deleted policy
// affects nothing.

// PolicyEffect is the parameter of the SQL function retention_policy_effect:
// the cluster scope (empty for all clusters), the label selectors, the
// evidence maximum per native type, the case-metadata maximum and the
// deletion budget.
type PolicyEffect struct {
	Clusters        []string          `json:"clusters"`
	NamespaceLabels map[string]string `json:"namespaceLabels,omitempty"`
	WorkloadLabels  map[string]string `json:"workloadLabels,omitempty"`
	Maxima          map[string]int64  `json:"maxima"`
	CaseMaximum     int64             `json:"caseMaximum"`
	Budget          int64             `json:"budget"`
}

// Effect returns the stored-deadline effect of one policy. SQL matches its
// label selectors against the labels recorded at admission; an artifact
// without recorded labels takes every policy of its cluster scope, since a
// privacy maximum may only err towards earlier deletion.
func Effect(p ScopedPolicy) PolicyEffect {
	out := PolicyEffect{Clusters: slices.Clone(p.Scope.ClusterIDs), NamespaceLabels: p.Scope.NamespaceLabels, WorkloadLabels: p.Scope.WorkloadLabels, Maxima: map[string]int64{}, CaseMaximum: CaseMetadataPolicy(p).EvidenceMaximum("other"), Budget: p.Policy.DeletionBudgetSeconds}
	if out.Clusters == nil {
		out.Clusters = []string{}
	}
	for _, name := range artifact.NativeTypeNames() {
		t, _ := artifact.LookupNativeType(name)
		out.Maxima[name] = p.Policy.EvidenceMaximum(t.EvidenceType)
	}
	return out
}

// Reasons reported for a change that was not evaluated.
const PreviewUnknownObject = "UnknownObject"

// RetentionChange is one proposed policy change. SourceClusterID is empty
// for the hub control namespace. Policy is the decoded spec for create and
// update.
type RetentionChange struct {
	Action, SourceClusterID, UID string
	Policy                       ScopedPolicy
}

// PreviewRow is one aggregate of retention_policy_effect over a proposal:
// the retained artifacts of one cluster and native type (or case metadata).
type PreviewRow struct {
	ClusterID, NativeType                      string
	CaseMetadata                               bool
	Scanned, Affected, ReadClosed, DeletionDue int
	EarliestExpiresAt, EarliestDeleteBy        time.Time
}

// RetentionPreviewGroup aggregates the artifacts of one cluster and class.
// The earliest dates are the new effective dates among affected artifacts.
type RetentionPreviewGroup struct {
	ClusterID, PrivacyClass, EvidenceType      string
	Scanned, Affected, ReadClosed, DeletionDue int
	Unknown                                    int
	EarliestExpiresAt, EarliestDeleteBy        time.Time
}

// PreviewIncomplete names a cluster whose result is incomplete.
type PreviewIncomplete struct{ ClusterID, Reason string }

// PreviewNotEvaluated names a change that could not be evaluated.
type PreviewNotEvaluated struct{ Action, SourceClusterID, UID, Reason string }

type RetentionPreview struct {
	Scanned, Affected, ReadClosed, DeletionDue, Unknown int
	EarliestExpiresAt, EarliestDeleteBy                 time.Time
	Groups                                              []RetentionPreviewGroup
	Incomplete                                          []PreviewIncomplete
	NotEvaluated                                        []PreviewNotEvaluated
	// BaselineChanged reports that the proposed policy set would no longer
	// hold exactly one baseline, which suspends new collection.
	BaselineChanged bool
	ObservedAt      time.Time
}

// Complete reports whether every change was evaluated.
func (p RetentionPreview) Complete() bool {
	return len(p.Incomplete) == 0 && len(p.NotEvaluated) == 0
}

// PlanPreview applies the proposal to the current policy set. It returns the
// effects to aggregate (created and updated policies only), the changes that
// name no current policy and whether the baseline count changes.
func PlanPreview(changes []RetentionChange, current []ScopedPolicy) ([]PolicyEffect, []PreviewNotEvaluated, bool, error) {
	if len(changes) < 1 {
		return nil, nil, false, ErrInvalid
	}
	set := slices.Clone(current)
	var effects []PolicyEffect
	var skipped []PreviewNotEvaluated
	seen := map[string]bool{}
	for n, c := range changes {
		if c.SourceClusterID != "" && !authorization.UUID(c.SourceClusterID) {
			return nil, nil, false, ErrInvalid
		}
		switch c.Action {
		case "create":
			if c.UID != "" {
				return nil, nil, false, ErrInvalid
			}
		case "update", "delete":
			if !identity.Text(c.UID, 64) || seen[c.UID] || (c.Action == "delete" && c.Policy.Name != "") {
				return nil, nil, false, ErrInvalid
			}
			seen[c.UID] = true
		default:
			return nil, nil, false, ErrInvalid
		}
		at := slices.IndexFunc(set, func(s ScopedPolicy) bool { return s.Policy.Revision.UID == c.UID })
		if c.Action != "create" && (at < 0 || c.SourceClusterID != "") {
			skipped = append(skipped, PreviewNotEvaluated{c.Action, c.SourceClusterID, c.UID, PreviewUnknownObject})
			continue
		}
		policy := c.Policy
		switch c.Action {
		case "delete":
			set = slices.Delete(set, at, at+1)
			continue
		case "create":
			policy.Name = "proposed-" + strconv.Itoa(n+1)
			policy.Policy.Revision = identity.Revision{UID: policy.Name, Generation: 1, Digest: artifact.Digest{'p'}}
			set = append(set, policy)
		case "update":
			policy.Name = set[at].Name
			policy.Policy.Revision = identity.Revision{UID: c.UID, Generation: set[at].Policy.Revision.Generation + 1, Digest: artifact.Digest{'p'}}
			set[at] = policy
		}
		if policy.Policy.Baseline != policy.Scope.Empty() || !policy.Valid() {
			return nil, nil, false, ErrInvalid
		}
		effects = append(effects, Effect(policy))
	}
	baselines := 0
	for _, p := range set {
		if p.Policy.Baseline {
			baselines++
		}
	}
	return effects, skipped, baselines != 1, nil
}

// SummarizePreview groups the aggregate rows by cluster and evidence type.
func SummarizePreview(rows []PreviewRow, skipped []PreviewNotEvaluated, baselineChanged bool, now time.Time) RetentionPreview {
	out := RetentionPreview{NotEvaluated: skipped, BaselineChanged: baselineChanged, ObservedAt: now}
	groups := map[[2]string]*RetentionPreviewGroup{}
	for _, r := range rows {
		kind := "other"
		if t, ok := artifact.LookupNativeType(r.NativeType); ok && !r.CaseMetadata {
			kind = t.EvidenceType
		}
		key := [2]string{r.ClusterID, kind}
		g := groups[key]
		if g == nil {
			g = &RetentionPreviewGroup{ClusterID: r.ClusterID, PrivacyClass: "potentialPersonalData", EvidenceType: kind}
			groups[key] = g
		}
		g.Scanned += r.Scanned
		g.Affected += r.Affected
		g.ReadClosed += r.ReadClosed
		g.DeletionDue += r.DeletionDue
		out.Scanned += r.Scanned
		out.Affected += r.Affected
		out.ReadClosed += r.ReadClosed
		out.DeletionDue += r.DeletionDue
		if r.Affected > 0 {
			g.EarliestExpiresAt = earliest(g.EarliestExpiresAt, r.EarliestExpiresAt)
			g.EarliestDeleteBy = earliest(g.EarliestDeleteBy, r.EarliestDeleteBy)
			out.EarliestExpiresAt = earliest(out.EarliestExpiresAt, r.EarliestExpiresAt)
			out.EarliestDeleteBy = earliest(out.EarliestDeleteBy, r.EarliestDeleteBy)
		}
	}
	for _, g := range groups {
		out.Groups = append(out.Groups, *g)
	}
	// Earliest new deletions first, then unaffected groups by cluster.
	slices.SortFunc(out.Groups, func(a, b RetentionPreviewGroup) int {
		if a.EarliestDeleteBy.IsZero() != b.EarliestDeleteBy.IsZero() {
			if a.EarliestDeleteBy.IsZero() {
				return 1
			}
			return -1
		}
		return cmp.Or(a.EarliestDeleteBy.Compare(b.EarliestDeleteBy), cmp.Compare(a.ClusterID, b.ClusterID), cmp.Compare(a.EvidenceType, b.EvidenceType))
	})
	return out
}

func earliest(current, t time.Time) time.Time {
	if current.IsZero() {
		return t
	}
	return identity.Earlier(current, t)
}
