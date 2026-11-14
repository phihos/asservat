package capacity

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The SQL capacity source stores one pool record and one policy record per
// cluster under these kinds. They are derived from the Helm `capacity`
// values; no Kubernetes object of these kinds exists.
const (
	PoolKind   = "EvidenceStoragePool"
	PolicyKind = "EvidenceBudgetPolicy"
	// EligibilityLabel is the namespace label that opts a namespace out of
	// evidence collection (value "disabled"). The capacity reconciler
	// reports each namespace's eligibility under this key (REQ-CAP intro).
	EligibilityLabel = "asservat.io/evidence"
	eligible         = "enabled"
	ineligible       = "disabled"
	poolName         = "evidence"
	// maxObjects is the SQL backend qualification's object bound. Object
	// counts are split in proportion to bytes, so they never limit before
	// the byte counts do.
	maxObjects = 1000000000
	// contextReserveBytes keeps room for pod-status context records inside
	// each workload allocation (REQ-CAP-004).
	contextReserveBytes = 12353536
	// sqlSlotLimit is the SQL schema's per-policy account bound (00054).
	sqlSlotLimit = 10000
)

// CapacityValues are the Helm `capacity` values in bytes (ADR-335 D2,
// specs/contracts/capacity.schema.json). Zero means "derive the default".
type CapacityValues struct {
	EvidenceBytes, ShareBytes, LimitBytes, NamespaceLimitBytes int64
	Assurance                                                  string
}

// EligibleNamespace reports whether a namespace takes part in evidence
// collection: every namespace except system namespaces, the release
// namespace and namespaces labelled asservat.io/evidence: disabled.
func EligibleNamespace(name, release string, labels map[string]string) map[string]string {
	if name == release || name == "kube-system" || name == "kube-public" || name == "kube-node-lease" || labels[EligibilityLabel] == ineligible {
		return map[string]string{EligibilityLabel: ineligible}
	}
	return map[string]string{EligibilityLabel: eligible}
}

// amount gives b bytes of u their proportional share of maxObjects.
func amount(b, u int64) BudgetAmount {
	hi, lo := bits.Mul64(uint64(b), maxObjects)
	n, _ := bits.Div64(hi, lo, uint64(u))
	return BudgetAmount{b, max(1, int64(n))}
}

// DeriveBudget derives the pool and one policy per cluster (REQ-CAP-004).
// The system reserve is 1/16 of the evidence storage; the default share is
// the rest divided by max(8, clusters + 1); whatever is not protected is shared burst.
// Protected slots are split evenly over the clusters. evidenceStorage is
// already usable capacity, so the SQL safety margin is one 4 KiB block.
func DeriveBudget(v CapacityValues, clusters []string) (PoolBudgetInput, []PolicyBudgetInput, error) {
	u := v.EvidenceBytes
	if u <= 0 || u > 1<<50 || len(clusters) == 0 {
		return PoolBudgetInput{}, nil, ErrBudgetInvalid
	}
	system, safety := u/16, int64(4096)
	available := u - system - safety
	share := v.ShareBytes
	if share <= 0 {
		// Each cluster keeps at least one protected slot and a positive burst.
		share = available / max(8, int64(len(clusters))+1)
	}
	if share <= 0 || share > available {
		return PoolBudgetInput{}, nil, fmt.Errorf("%w: workload share %d of %d available bytes", ErrBudgetInvalid, share, available)
	}
	slots := available / share
	if slots*share == available {
		slots-- // keep a positive shared burst
	}
	per := min(slots/int64(len(clusters)), sqlSlotLimit)
	if per < 1 {
		return PoolBudgetInput{}, nil, fmt.Errorf("%w: a workload share of %d bytes leaves no protected slot for each of %d clusters", ErrBudgetInvalid, share, len(clusters))
	}
	burst := available - per*int64(len(clusters))*share
	hard := v.LimitBytes
	if hard <= 0 {
		hard = u / 10
	}
	hard = max(hard, share)
	namespace := v.NamespaceLimitBytes
	if namespace <= 0 {
		namespace = u
	}
	namespace = max(namespace, share)
	pool := PoolBudgetInput{Name: poolName, Capacity: amount(u, u), Safety: amount(safety, u), System: amount(system, u), Burst: amount(burst, u)}
	policies := make([]PolicyBudgetInput, 0, len(clusters))
	for _, c := range clusters {
		name := policyName(c)
		pool.Slots = append(pool.Slots, ProtectedSlotInput{Policy: name, Workloads: per, Protected: amount(share, u)})
		policies = append(policies, PolicyBudgetInput{Name: name, Pool: poolName, Cluster: c, Protected: amount(share, u), Hard: amount(hard, u),
			Context: amount(min(share, contextReserveBytes), u), NamespaceMaximum: amount(namespace, u), NamespaceAccounts: per})
	}
	if _, e := CompileProtectedPool(pool, policies); e != nil {
		return PoolBudgetInput{}, nil, e
	}
	return pool, policies, nil
}

func policyName(cluster string) string { return "cluster-" + cluster }

// SystemPoolUID is the stable identity of the installation's one pool.
func SystemPoolUID(installation string) string { return nameUUID(installation, "capacity/pool") }

// nameUUID is the RFC 9562 version 5 UUID of name in the space UUID.
func nameUUID(space, name string) string {
	b, _ := hex.DecodeString(strings.ReplaceAll(space, "-", ""))
	h := sha1.Sum(append(b, name...))
	h[6], h[8] = h[6]&0x0f|0x50, h[8]&0x3f|0x80
	x := hex.EncodeToString(h[:16])
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}

// ValuesSource is the capacity source: the Helm values of the current
// release revision. Every helm upgrade raises the revision, so a changed
// value is a new generation of the same records.
type ValuesSource struct {
	Installation, Cluster string
	Control               cfg.NamespaceRef
	Revision              int64
	Values                CapacityValues
	Clusters              []string // hub cluster first
	Now                   func() time.Time
}

var _ CapacitySourceReader = (*ValuesSource)(nil)

func (s *ValuesSource) ReadCapacitySource(ctx context.Context) (CapacitySourceObservation, error) {
	var zero CapacitySourceObservation
	if s == nil || ctx == nil || ctx.Err() != nil || s.Now == nil || !authorization.UUID(s.Installation) || s.Revision < 1 || s.Revision > 2147483647 {
		return zero, cfg.ErrUnavailable
	}
	pool, policies, e := DeriveBudget(s.Values, s.Clusters)
	if e != nil {
		return zero, e
	}
	assurance := s.Values.Assurance
	if assurance == "" {
		assurance = "bestEffort"
	}
	now := s.Now()
	rv := strconv.FormatInt(s.Revision, 10)
	resource := func(kind, name, uid string, spec any) (cfg.Resource, CapacitySourceVersion) {
		b, _ := json.Marshal(spec)
		d := artifact.Digest(sha256.Sum256(b))
		r := cfg.Resource{ClusterID: s.Cluster, Namespace: s.Control.Name, NamespaceUID: s.Control.UID, Kind: kind, Name: name, UID: uid, ResourceVersion: rv, Generation: s.Revision, SpecDigest: d}
		return r, sourceVersion(r, d)
	}
	snap := CapacitySnapshot{ClusterID: s.Cluster, ControlNamespace: s.Control, PoolResourceVersion: rv, PolicyResourceVersion: rv, ObservedAt: now, FreshUntil: now.Add(CapacitySourceInterval)}
	r, v := resource(PoolKind, poolName, SystemPoolUID(s.Installation), struct {
		Assurance string
		Budget    PoolBudgetInput
	}{assurance, pool})
	snap.Pools = []PoolObservation{{Resource: r, StorageProfile: poolName, Assurance: assurance, Budget: &pool}}
	versions := []CapacitySourceVersion{v}
	for i := range policies {
		p := &policies[i]
		uid := nameUUID(s.Installation, "capacity/policy/"+p.Cluster)
		scope := BudgetScope{ClusterID: p.Cluster, NamespaceLabels: map[string]string{EligibilityLabel: eligible}}
		r, v := resource(PolicyKind, p.Name, uid, struct {
			Scope  BudgetScope
			Budget PolicyBudgetInput
		}{scope, *p})
		snap.Policies = append(snap.Policies, BudgetPolicyObservation{Resource: r, Scope: &scope, Pool: poolName, Budget: p})
		versions = append(versions, v)
	}
	out := CapacitySourceObservation{Snapshot: snap, Versions: versions}
	if out.Digest, e = CapacitySourceDigest(snap, versions); e != nil {
		return zero, e
	}
	return out, nil
}
