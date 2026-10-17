package capacity

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityPermissionScopeLimit = 1024

// AcceptedCapacityScope contains no subject, group, client or audit payload.
// It is a candidate enrollment scope from an acknowledged live maintainer
// assignment. It cannot authorize a collection; all caller/deny checks remain
// on the separate actual capture request path.
type AcceptedCapacityScope struct {
	BasisKey, BasisUID, ClusterID, NamespaceUID string
	ScopeDigest                                 artifact.Digest
	WorkloadUIDs                                []string
	NotAfter                                    *time.Time
}

func (s AcceptedCapacityScope) valid(now time.Time) bool {
	if !identity.Text(s.BasisKey, 512) || !identity.Text(s.BasisUID, 64) || !authorization.UUID(s.ClusterID) || !identity.Text(s.NamespaceUID, 64) || s.ScopeDigest == (artifact.Digest{}) || !identity.Strings(s.WorkloadUIDs, 1024, 64) || s.NotAfter != nil && !now.Before(*s.NotAfter) {
		return false
	}
	seen := map[string]bool{}
	for _, id := range s.WorkloadUIDs {
		if seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func (s AcceptedCapacityScope) Covers(k WorkloadCapacityKey, now time.Time) bool {
	return k.Valid() && s.valid(now) && s.ClusterID == k.ClusterID && s.NamespaceUID == k.NamespaceUID && (len(s.WorkloadUIDs) == 0 || slices.Contains(s.WorkloadUIDs, k.WorkloadUID))
}

type AcceptedCapacityPermissions struct {
	RootID, Epoch          string
	Sequence               int64
	TrustDigest            artifact.Digest
	ObservedAt, FreshUntil time.Time
	Scopes                 []AcceptedCapacityScope
}

func (v AcceptedCapacityPermissions) Valid(now time.Time) bool {
	if !authorization.UUID(v.RootID) || !authorization.UUID(v.Epoch) || v.Sequence < 0 || v.TrustDigest == (artifact.Digest{}) || !identity.Fresh(v.ObservedAt, v.FreshUntil, now, CapacitySourceInterval) || len(v.Scopes) > CapacityPermissionScopeLimit {
		return false
	}
	seen := map[string]bool{}
	for _, s := range v.Scopes {
		if !s.valid(now) || seen[s.BasisKey] || s.NotAfter != nil && v.FreshUntil.After(*s.NotAfter) {
			return false
		}
		seen[s.BasisKey] = true
	}
	return true
}

type CapacityPermissionReader interface {
	ReadCapacityPermissions(context.Context, artifact.RecoveryProof) (AcceptedCapacityPermissions, error)
}
