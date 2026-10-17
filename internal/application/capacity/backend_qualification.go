package capacity

import (
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityBackendLayout = "dedicated-capacity-envelope/v1"

// This is a protected installer measurement/ownership reference. CapacityID
// names the dedicated backing envelope after replication/EC overhead. Reusing
// it in two source pools would pledge the same space twice and is rejected.
// The two store identities may be distinct purpose-specific buckets within
// that one qualified envelope; neither is inferred from the CRD's assurance.
type CapacityBackendQualification struct {
	Layout, ID                                        string
	Digest                                            artifact.Digest
	PoolUID, StorageProfile                           string
	CapacityID, PoolID, EvidenceStoreID, AuditStoreID string
	Usable                                            BudgetAmount
}

func (v CapacityBackendQualification) Valid() bool {
	return v.Layout == CapacityBackendLayout && authorization.UUID(v.ID) && v.Digest != (artifact.Digest{}) && identity.Text(v.PoolUID, 64) && identity.Text(v.StorageProfile, 63) && authorization.UUID(v.CapacityID) && authorization.UUID(v.PoolID) && authorization.UUID(v.EvidenceStoreID) && authorization.UUID(v.AuditStoreID) && v.Usable.positive() && v.Usable.Bytes <= 1<<50 && v.Usable.Objects <= 1000000000
}

type CapacityNamespaceQualification struct {
	ClusterID string
	Digest    artifact.Digest
	Keys      []string
}

// The immutable installed input closes the actual quantities, metadata
// protection and backend ownership. Accepted source observations reference its
// exact ID/digest. That digest identifies accepted qualification evidence; it
// is not a self-referential hash of this object containing the digest itself.
// The protected projection separately binds these exact bytes and role pins.
type CapacityQualification struct {
	ID              string
	Digest          artifact.Digest
	RootBacking     RootBackingInput
	NamespaceGuards []CapacityNamespaceQualification
	Backends        []CapacityBackendQualification
}

func (v CapacityQualification) Valid() bool {
	if !authorization.UUID(v.ID) || v.Digest == (artifact.Digest{}) || v.RootBacking.QualificationID != v.ID || v.RootBacking.QualificationDigest != v.Digest || len(v.NamespaceGuards) < 1 || len(v.NamespaceGuards) > 16 || len(v.Backends) < 1 || len(v.Backends) > 16 {
		return false
	}
	clusters := map[string]bool{}
	for _, g := range v.NamespaceGuards {
		if !authorization.UUID(g.ClusterID) || g.Digest == (artifact.Digest{}) || clusters[g.ClusterID] || len(g.Keys) < 1 || len(g.Keys) > 256 || !slices.IsSorted(g.Keys) {
			return false
		}
		for i, k := range g.Keys {
			if !identity.Text(k, 253) || i > 0 && k == g.Keys[i-1] {
				return false
			}
		}
		clusters[g.ClusterID] = true
	}
	// Separate maps avoid falsely rejecting the same logical ID in different
	// identity namespaces while preventing duplicate ownership in each one.
	seen := []map[string]bool{{}, {}, {}, {}}
	system := false
	for _, b := range v.Backends {
		if !b.Valid() {
			return false
		}
		for i, key := range []string{b.PoolUID, b.CapacityID, b.PoolID, b.EvidenceStoreID} {
			if seen[i][key] {
				return false
			}
			seen[i][key] = true
		}
		if b.PoolUID == v.RootBacking.SystemPoolUID {
			if b.AuditStoreID != v.RootBacking.Capture.Policy.StoreID {
				return false
			}
			system = true
		}
	}
	return system
}

func (v CapacityQualification) BackendFor(p ProtectedPoolPlan) (CapacityBackendQualification, error) {
	if !v.Valid() {
		return CapacityBackendQualification{}, ErrBudgetInvalid
	}
	for _, b := range v.Backends {
		if b.PoolUID == p.UID {
			if p.Format != ProtectedPoolPlanFormat || b.StorageProfile != p.StorageProfile || !b.Usable.contains(p.Capacity) {
				return CapacityBackendQualification{}, ErrBudgetFull
			}
			return b, nil
		}
	}
	return CapacityBackendQualification{}, ErrBudgetInvalid
}

// The production compiler must call this protected boundary; the lower-level
// arithmetic compiler intentionally cannot establish backend/source ownership.
func CompileQualifiedRootBacking(q CapacityQualification, systemPool ProtectedPoolPlan) (RootBackingPlan, error) {
	if !q.Valid() || systemPool.UID != q.RootBacking.SystemPoolUID {
		return RootBackingPlan{}, ErrBudgetInvalid
	}
	if _, e := q.BackendFor(systemPool); e != nil {
		return RootBackingPlan{}, e
	}
	return CompileRootBacking(q.RootBacking, systemPool)
}
