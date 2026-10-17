package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"maps"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

const CapacityEnrollmentPlanFormat = "capacity-enrollment-plan/v1"
const CapacityEnrollmentPlanBytes = 32 << 10

// EnrollmentPlan carries the complete arithmetic input to the SQL boundary,
// rather than a digest whose missing contents an adapter would have to guess.
// Its private immutable strings prevent later mutation of decoded source maps.
// It is configuration, never a permission, SQL effect receipt or caller account.
type EnrollmentPlan struct {
	value                                     enrollmentPlanValue
	canonical, poolCanonical, sourceCanonical string
	digest                                    artifact.Digest
}

// The account row retains this small exact value. The complete pool plan is
// passed with it and independently recomputed from the locked accepted source;
// the pool row retains that complete plan only once for all of its accounts.
type enrollmentPlanValue struct {
	Format, RootID, InstallationID, QualificationID, AccountVersion string
	QualificationDigest, SourceDigest, PoolDigest                   artifact.Digest
	PoolName, PoolUID, PolicyName, PolicyUID, ClusterID             string
	PoolGeneration, PolicyGeneration                                int64
	PolicyDigest                                                    artifact.Digest
	Budget                                                          PolicyBudgetInput
	PolicySlots                                                     int64
}

func CompileEnrollmentPlan(source AcceptedCapacitySource, selected SelectedBudget, accountVersion string, now time.Time) (EnrollmentPlan, error) {
	var zero EnrollmentPlan
	if !source.Valid(now) || !identity.Text(accountVersion, 64) || !identity.Fresh(selected.ObservedAt, selected.FreshUntil, now, CapacitySourceInterval) {
		return zero, cfg.ErrUnavailable
	}
	pool, e := CompileProtectedPoolPlan(source.Observation.Snapshot, selected.Pool.Name)
	if e != nil {
		return zero, e
	}
	if pool.UID != selected.Pool.UID || pool.Generation != selected.Pool.Generation || pool.Digest != selected.Pool.SpecDigest || pool.StorageProfile != selected.StorageProfile {
		return zero, cfg.ErrChanged
	}
	var policy *ProtectedPolicyPlan
	for i := range pool.Policies {
		if pool.Policies[i].Name == selected.Policy.Name {
			policy = &pool.Policies[i]
			break
		}
	}
	if policy == nil || policy.UID != selected.Policy.UID || policy.Generation != selected.Policy.Generation || policy.Digest != selected.Policy.SpecDigest || policy.Budget != selected.Budget || policy.Scope.ClusterID != selected.Scope.ClusterID || !maps.Equal(policy.Scope.NamespaceLabels, selected.Scope.NamespaceLabels) {
		return zero, cfg.ErrChanged
	}
	poolBytes, poolDigest, e := CanonicalProtectedPoolPlan(source.Observation.Snapshot, pool.Name)
	if e != nil {
		return zero, e
	}
	sourceBytes, e := capacitySelectedSourceBytes(source.Observation.Snapshot, pool.Name)
	if e != nil {
		return zero, e
	}
	sourceDigest := sha256.Sum256(sourceBytes)
	v := enrollmentPlanValue{Format: CapacityEnrollmentPlanFormat, RootID: source.RootID, InstallationID: source.InstallationID, QualificationID: source.QualificationID, AccountVersion: accountVersion,
		QualificationDigest: source.QualificationDigest, SourceDigest: sourceDigest, PoolDigest: poolDigest, PoolName: pool.Name, PoolUID: pool.UID, PolicyName: policy.Name, PolicyUID: policy.UID, ClusterID: policy.Scope.ClusterID,
		PoolGeneration: pool.Generation, PolicyGeneration: policy.Generation, PolicyDigest: policy.Digest, Budget: policy.Budget, PolicySlots: policy.Slots}
	b, e := json.Marshal(v)
	if e != nil || len(b) > CapacityEnrollmentPlanBytes {
		return zero, cfg.ErrUnavailable
	}
	h := sha256.New()
	_, _ = h.Write([]byte("asservat-capacity-enrollment/json-v1\x00"))
	_, _ = h.Write(b)
	var digest artifact.Digest
	copy(digest[:], h.Sum(nil))
	return EnrollmentPlan{value: v, canonical: string(b), poolCanonical: string(poolBytes), sourceCanonical: string(sourceBytes), digest: digest}, nil
}

func (p EnrollmentPlan) Digest() artifact.Digest { return p.digest }
func (p EnrollmentPlan) AccountVersion() string  { return p.value.AccountVersion }
func (p EnrollmentPlan) Matches(key WorkloadCapacityKey, installation string, source, digest artifact.Digest) bool {
	return len(p.canonical) > 0 && len(p.canonical) <= CapacityEnrollmentPlanBytes && len(p.poolCanonical) > 0 && len(p.poolCanonical) <= ProtectedPoolPlanBytes && len(p.sourceCanonical) > 0 && len(p.sourceCanonical) <= CapacitySourceBytes && p.digest != (artifact.Digest{}) && p.digest == digest && p.value.SourceDigest == source && p.value.RootID == key.RootID && p.value.ClusterID == key.ClusterID && p.value.InstallationID == installation
}

// CanonicalValues returns copies for the purpose-fixed SQL RPC. The small plan
// and complete pool bytes have different versioned digests; no secret is held.
func (p EnrollmentPlan) CanonicalValues() (plan, pool, source []byte, err error) {
	if p.canonical == "" || p.poolCanonical == "" || p.sourceCanonical == "" || p.digest == (artifact.Digest{}) {
		return nil, nil, nil, cfg.ErrUnavailable
	}
	return []byte(p.canonical), []byte(p.poolCanonical), []byte(p.sourceCanonical), nil
}
