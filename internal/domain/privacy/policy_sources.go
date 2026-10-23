package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// Source topology is protected installation configuration. A caller cannot
// choose to omit a cluster's local policy source to obtain a weaker ceiling.
type PolicySourceRef struct {
	ClusterID, ControlNamespaceUID string
	Hub                            bool
	ProtectionDigest               artifact.Digest
}
type PolicyTopology struct {
	RootID, TargetClusterID string
	Revision                identity.Revision
	Sources                 []PolicySourceRef
	ObservedAt, FreshUntil  time.Time
}

// PolicyTopologyInterval bounds one topology observation. The topology is an
// installer-pinned immutable ConfigMap whose content digest every read checks,
// so the authorized 30 s recheck cadence applies (ADR-200 revision 2026-10-23).
const PolicyTopologyInterval = 30 * time.Second

func (t PolicyTopology) Valid(now time.Time) bool {
	if !authorization.UUID(t.RootID) || !authorization.UUID(t.TargetClusterID) || !t.Revision.Valid() || !identity.Fresh(t.ObservedAt, t.FreshUntil, now, PolicyTopologyInterval) || len(t.Sources) < 1 || len(t.Sources) > 2 {
		return false
	}
	hubs := 0
	seen := map[string]bool{}
	for _, s := range t.Sources {
		key := s.ClusterID + "/" + s.ControlNamespaceUID
		if !authorization.UUID(s.ClusterID) || !identity.Text(s.ControlNamespaceUID, 64) || s.ProtectionDigest == (artifact.Digest{}) || seen[key] || (!s.Hub && s.ClusterID != t.TargetClusterID) {
			return false
		}
		seen[key] = true
		if s.Hub {
			hubs++
		}
	}
	return hubs == 1
}

// AcceptedSource is supplied by C-01's guarded projection, never by CRD status.
// Ready requires accepted initial values, complete transition history/current
// guard, durable authority audit and reconciliation of retained obligations.
type AcceptedSource struct {
	RootID                 string
	Epoch                  string
	Snapshot               PolicySnapshot
	Acceptance             identity.Revision
	ProtectionDigest       artifact.Digest
	Ready                  bool
	ObservedAt, FreshUntil time.Time
}

// RetentionSourceInterval bounds an accepted retention source observation:
// 30 seconds after its original LIST/guard observation under the maintainer's
// relaxed recheck cadence (ADR-200 revision 2026-10-23). A raw Kubernetes LIST
// or guard proof keeps five seconds; invalidation, suspension and takeover
// still clear the accepted observation at once, and bookmarks never renew it.
const RetentionSourceInterval = artifact.RetentionProofInterval

func (s AcceptedSource) Valid(now time.Time) bool {
	return authorization.UUID(s.RootID) && authorization.UUID(s.Epoch) && s.Ready && s.Snapshot.validWithin(now, RetentionSourceInterval) && s.Acceptance.Valid() && s.ProtectionDigest != (artifact.Digest{}) && identity.Fresh(s.ObservedAt, s.FreshUntil, now, RetentionSourceInterval)
}
