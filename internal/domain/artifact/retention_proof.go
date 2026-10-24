package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// RetentionProof carries the complete protected configuration versions checked
// for one target. It is internal control provenance, not a bearer grant or an
// instruction to choose policy sources. Final SQL effects must recheck it.
// Fixed-size source storage makes copies independent and prevents hidden extras.
type RetentionProof struct {
	RootID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Topology, Policy, Selectors                          identity.Revision
	SourceCount                                          int
	Sources                                              [2]RetentionSourceVersion
	ObservedAt, ValidUntil                               time.Time
}
type RetentionSourceVersion struct {
	ClusterID, ControlNamespaceUID, Epoch string
	Hub                                   bool
	ProtectionDigest, SnapshotDigest      Digest
	Acceptance                            identity.Revision
}

func (s RetentionSourceVersion) Valid() bool {
	return uuid(s.ClusterID) && identity.Text(s.ControlNamespaceUID, 64) && uuid(s.Epoch) && s.ProtectionDigest != (Digest{}) && s.SnapshotDigest != (Digest{}) && uuid(s.Acceptance.UID) && s.Acceptance.Valid()
}

// RetentionProofInterval bounds a retention proof's observation interval. It
// derives from accepted retention sources current for 30 seconds after their
// own observation (ADR-200 revision 2026-10-23); invalidation still applies at
// once because every effect rechecks the current source rows.
const RetentionProofInterval = 30 * time.Second

func (p RetentionProof) Valid(now time.Time) bool {
	if !uuid(p.RootID) || !uuid(p.ClusterID) || !identity.Text(p.NamespaceUID, 64) || !identity.Text(p.WorkloadUID, 64) || !identity.Text(p.PodUID, 64) || !p.Topology.Valid() || !p.Policy.Valid() || !p.Selectors.Valid() || !identity.Fresh(p.ObservedAt, p.ValidUntil, now, RetentionProofInterval) || p.SourceCount < 1 || p.SourceCount > 2 {
		return false
	}
	for i, s := range p.Sources {
		if i >= p.SourceCount {
			if s != (RetentionSourceVersion{}) {
				return false
			}
			continue
		}
		if !s.Valid() || s.Hub != (i == 0) || (i == 1 && (s.ClusterID != p.ClusterID || (s.ClusterID == p.Sources[0].ClusterID && s.ControlNamespaceUID == p.Sources[0].ControlNamespaceUID))) {
			return false
		}
	}
	return true
}
func (p RetentionProof) Matches(root, cluster, namespace, workload, pod string) bool {
	return p.RootID == root && p.ClusterID == cluster && p.NamespaceUID == namespace && p.WorkloadUID == workload && p.PodUID == pod
}
