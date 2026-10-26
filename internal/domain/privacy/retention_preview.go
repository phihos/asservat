package privacy

import (
	"cmp"
	"errors"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Retention impact preview (ADR-240, REQ-PRV-002). It applies a proposed
// EvidenceRetentionPolicy change to the retained catalog exactly as the
// catch-up would after acceptance: HistoricalSourcePolicies selects the
// applicable policies of the changed source and ApplyRetainedObligation
// computes the new effective dates. Both only ever shorten, so a longer
// maximum never moves an already bound date, and a newly encountered label
// selector without qualified history is Unknown, never assumed. The preview
// is advisory: it grants, persists and changes nothing.
const (
	// MaxRetentionPreviewChanges bounds one proposal.
	MaxRetentionPreviewChanges = 16
	// MaxRetentionPreviewArtifacts bounds the catalog scan of one preview.
	MaxRetentionPreviewArtifacts = 10000
	// MaxRetentionPreviewSources bounds the accepted sources read.
	MaxRetentionPreviewSources = 256
)

// ErrPreviewLimit marks a proposal beyond the preview bounds.
var ErrPreviewLimit = errors.New("retention preview exceeds its bounds")

// Reasons reported for a cluster whose result is incomplete or a change that
// was not evaluated.
const (
	PreviewSourceUnavailable = "SourceUnavailable"
	PreviewSourceAmbiguous   = "SourceAmbiguous"
	PreviewUnknownObject     = "UnknownObject"
)

// RetentionChange is one proposed policy change. SourceClusterID is empty
// for the hub source, otherwise the cluster whose local control namespace
// holds the object. Policy is the decoded spec for create and update; its
// revision UID and generation are assigned by the preview.
type RetentionChange struct {
	Action, SourceClusterID, UID string
	Policy                       ScopedPolicy
}

// PreviewSource is one retention source of the installation with its latest
// accepted policy snapshot (nil before the first acceptance). Ready is the
// ordinary source readiness: accepted, fresh, audited and caught up.
type PreviewSource struct {
	Ref     PolicySourceRef
	Ready   bool
	Current *PolicySnapshot
}

// PreviewCatalog is the bounded retained catalog read of one preview: the
// sources and the retained context artifacts whose deletion deadline has not
// yet passed. Unreadable counts, per cluster, retained rows that could not be
// decoded into a retained artifact; they are reported as Unknown.
type PreviewCatalog struct {
	Sources    []PreviewSource
	Artifacts  []RetainedArtifact
	Unreadable map[string]int
	Truncated  bool
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
	Truncated                                           bool
	// BaselineChanged reports that the proposed hub source would no longer
	// hold exactly one baseline, which suspends new collection.
	BaselineChanged bool
	ObservedAt      time.Time
}

// Complete reports whether every cluster and change was evaluated over the
// whole bounded catalog.
func (p RetentionPreview) Complete() bool {
	return len(p.Incomplete) == 0 && len(p.NotEvaluated) == 0 && !p.Truncated
}

type proposedSource struct {
	source   PreviewSource
	snapshot PolicySnapshot
}

// PreviewRetention computes the preview at now. ErrInvalid marks an invalid
// proposal, ErrPreviewLimit one beyond the bounds and ErrUnavailable a
// catalog without exactly one hub source.
func PreviewRetention(changes []RetentionChange, catalog PreviewCatalog, now time.Time) (RetentionPreview, error) {
	var out RetentionPreview
	if len(changes) < 1 || len(changes) > MaxRetentionPreviewChanges || len(catalog.Sources) > MaxRetentionPreviewSources || len(catalog.Artifacts) > MaxRetentionPreviewArtifacts {
		return out, ErrPreviewLimit
	}
	hubs := 0
	for _, s := range catalog.Sources {
		if s.Ref.Hub {
			hubs++
		}
	}
	if hubs != 1 {
		return out, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, c := range changes {
		key := c.SourceClusterID + "/" + c.UID
		if c.SourceClusterID != "" && !authorization.UUID(c.SourceClusterID) {
			return out, ErrInvalid
		}
		switch c.Action {
		case "create":
			if c.UID != "" {
				return out, ErrInvalid
			}
		case "update", "delete":
			if !identity.Text(c.UID, 64) || seen[key] {
				return out, ErrInvalid
			}
			seen[key] = true
		default:
			return out, ErrInvalid
		}
	}
	incomplete := map[string]string{}
	proposed := map[string]*proposedSource{}
	order := []string{}
	for n, c := range changes {
		if c.Action == "delete" && (c.Policy.Name != "" || c.Policy.Policy.Revision != (identity.Revision{})) {
			return out, ErrInvalid
		}
		index, found := previewSourceIndex(catalog.Sources, c.SourceClusterID)
		if found == previewAmbiguous {
			out.NotEvaluated = append(out.NotEvaluated, PreviewNotEvaluated{c.Action, c.SourceClusterID, c.UID, PreviewSourceAmbiguous})
			incomplete[c.SourceClusterID] = PreviewSourceUnavailable
			continue
		}
		key := "local/" + c.SourceClusterID
		if c.SourceClusterID == "" {
			key = "hub"
		}
		p := proposed[key]
		if p == nil {
			// A local source not accepted yet: its policies apply to this
			// cluster once accepted, so the cluster's result is incomplete.
			source := PreviewSource{Ref: PolicySourceRef{ClusterID: c.SourceClusterID, ControlNamespaceUID: "unaccepted-local-source"}}
			if found == previewFound {
				source = catalog.Sources[index]
			} else {
				incomplete[c.SourceClusterID] = PreviewSourceUnavailable
			}
			p = &proposedSource{source: source, snapshot: PolicySnapshot{SourceClusterID: source.Ref.ClusterID, ControlNamespaceUID: source.Ref.ControlNamespaceUID, Hub: source.Ref.Hub}}
			if source.Current != nil {
				p.snapshot.Policies = slices.Clone(source.Current.Policies)
			}
			proposed[key] = p
			order = append(order, key)
		}
		at := slices.IndexFunc(p.snapshot.Policies, func(s ScopedPolicy) bool { return s.Policy.Revision.UID == c.UID })
		if c.Action != "create" && at < 0 {
			out.NotEvaluated = append(out.NotEvaluated, PreviewNotEvaluated{c.Action, c.SourceClusterID, c.UID, PreviewUnknownObject})
			continue
		}
		switch c.Action {
		case "delete":
			// Deleting a policy never lengthens a bound date; it is kept in
			// the proposed set only by its absence.
			p.snapshot.Policies = slices.Delete(p.snapshot.Policies, at, at+1)
		case "create", "update":
			policy := c.Policy
			if policy.Policy.Baseline != (p.source.Ref.Hub && policy.Scope.Empty()) {
				return out, ErrInvalid
			}
			if c.Action == "create" {
				policy.Name = "proposed-" + strconv.Itoa(n+1)
				policy.Policy.Revision.UID = policy.Name
				policy.Policy.Revision.Generation = 1
				p.snapshot.Policies = append(p.snapshot.Policies, policy)
			} else {
				current := p.snapshot.Policies[at]
				policy.Name = current.Name
				policy.Policy.Revision.UID = current.Policy.Revision.UID
				policy.Policy.Revision.Generation = current.Policy.Revision.Generation + 1
				p.snapshot.Policies[at] = policy
			}
		}
	}
	// The proposed snapshot is never persisted or compared; its revision only
	// satisfies the snapshot shape that the catch-up functions check.
	snapshots := make([]PolicySnapshot, 0, len(order))
	for _, key := range order {
		p := proposed[key]
		p.snapshot.ObservedAt, p.snapshot.FreshUntil = now, now.Add(5*time.Second)
		p.snapshot.Revision = identity.Revision{UID: p.snapshot.ControlNamespaceUID, Generation: 1, Digest: artifact.Digest{'p'}}
		if !p.snapshot.Valid(now) {
			return RetentionPreview{}, ErrInvalid
		}
		if p.snapshot.Hub {
			baselines := 0
			for _, s := range p.snapshot.Policies {
				if s.Policy.Baseline {
					baselines++
				}
			}
			out.BaselineChanged = baselines != 1
		}
		snapshots = append(snapshots, p.snapshot)
	}
	// Hub first: the catch-up applies each source's oldest checkpoint
	// independently; the combined result does not depend on the order.
	slices.SortStableFunc(snapshots, func(a, b PolicySnapshot) int {
		if a.Hub != b.Hub {
			if a.Hub {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.SourceClusterID, b.SourceClusterID)
	})
	notReadyHub := false
	for _, s := range catalog.Sources {
		if s.Ready {
			continue
		}
		if s.Ref.Hub {
			notReadyHub = true
		} else {
			incomplete[s.Ref.ClusterID] = PreviewSourceUnavailable
		}
	}
	groups := map[[3]string]*RetentionPreviewGroup{}
	group := func(cluster, class, kind string) *RetentionPreviewGroup {
		key := [3]string{cluster, class, kind}
		if groups[key] == nil {
			groups[key] = &RetentionPreviewGroup{ClusterID: cluster, PrivacyClass: class, EvidenceType: kind}
		}
		return groups[key]
	}
	clusters := map[string]bool{}
	for _, r := range catalog.Artifacts {
		cluster := r.Input.Target.ClusterID
		clusters[cluster] = true
		g := group(cluster, r.Input.PrivacyClass, r.Input.EvidenceType)
		g.Scanned++
		out.Scanned++
		after, known := previewArtifact(r, snapshots)
		if !known {
			g.Unknown++
			out.Unknown++
			continue
		}
		before := r.Effective
		if !after.ExpiresAt.Before(before.ExpiresAt) && !after.DeleteBy.Before(before.DeleteBy) {
			continue
		}
		g.Affected++
		out.Affected++
		if !now.Before(after.ExpiresAt) && now.Before(before.ExpiresAt) {
			g.ReadClosed++
			out.ReadClosed++
		}
		if !now.Before(after.DeleteBy) {
			g.DeletionDue++
			out.DeletionDue++
		}
		g.EarliestExpiresAt = earliest(g.EarliestExpiresAt, after.ExpiresAt)
		g.EarliestDeleteBy = earliest(g.EarliestDeleteBy, after.DeleteBy)
		out.EarliestExpiresAt = earliest(out.EarliestExpiresAt, after.ExpiresAt)
		out.EarliestDeleteBy = earliest(out.EarliestDeleteBy, after.DeleteBy)
	}
	for cluster, n := range catalog.Unreadable {
		if n <= 0 || !authorization.UUID(cluster) {
			return RetentionPreview{}, ErrInvalid
		}
		clusters[cluster] = true
		// Rows that cannot be decoded have no known class; never assumed.
		g := group(cluster, "unknown", "other")
		g.Scanned += n
		g.Unknown += n
		out.Scanned += n
		out.Unknown += n
	}
	if notReadyHub {
		for cluster := range clusters {
			incomplete[cluster] = PreviewSourceUnavailable
		}
		for _, s := range catalog.Sources {
			incomplete[s.Ref.ClusterID] = PreviewSourceUnavailable
		}
	}
	delete(incomplete, "")
	for cluster, reason := range incomplete {
		out.Incomplete = append(out.Incomplete, PreviewIncomplete{cluster, reason})
	}
	slices.SortFunc(out.Incomplete, func(a, b PreviewIncomplete) int { return cmp.Compare(a.ClusterID, b.ClusterID) })
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
		return cmp.Or(a.EarliestDeleteBy.Compare(b.EarliestDeleteBy), cmp.Compare(a.ClusterID, b.ClusterID), cmp.Compare(a.PrivacyClass, b.PrivacyClass), cmp.Compare(a.EvidenceType, b.EvidenceType))
	})
	out.Truncated = catalog.Truncated
	out.ObservedAt = now
	return out, nil
}

const (
	previewFound = iota
	previewMissing
	previewAmbiguous
)

// previewSourceIndex finds the hub source (empty cluster) or the one local
// source of a cluster.
func previewSourceIndex(sources []PreviewSource, cluster string) (int, int) {
	found, n := -1, 0
	for i, s := range sources {
		if (cluster == "" && s.Ref.Hub) || (cluster != "" && !s.Ref.Hub && s.Ref.ClusterID == cluster) {
			found = i
			n++
		}
	}
	switch n {
	case 0:
		return -1, previewMissing
	case 1:
		return found, previewFound
	}
	return -1, previewAmbiguous
}

// previewArtifact applies each changed source in turn, as the catch-up does
// for each accepted checkpoint, carrying the merged policy origins forward.
// known is false when any source cannot be applied from qualified history.
func previewArtifact(r RetainedArtifact, snapshots []PolicySnapshot) (Deadlines, bool) {
	r.OriginPolicies = slices.Clone(r.OriginPolicies)
	for _, s := range snapshots {
		if !s.Hub && s.SourceClusterID != r.Input.Target.ClusterID {
			continue
		}
		policies, err := HistoricalSourcePolicies(s, r)
		if err != nil {
			return Deadlines{}, false
		}
		deadlines, refs, err := ApplyRetainedObligation(r, policies)
		if err != nil {
			return Deadlines{}, false
		}
		if len(refs) > 0 {
			if r.OriginPolicies, err = MergePolicyOrigins(r.OriginPolicies, refs); err != nil {
				return Deadlines{}, false
			}
		}
		r.Effective = deadlines
	}
	return r.Effective, true
}

func earliest(current, t time.Time) time.Time {
	if current.IsZero() {
		return t
	}
	return identity.Earlier(current, t)
}
