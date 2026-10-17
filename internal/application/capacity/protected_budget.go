package capacity

import (
	"errors"
	"math"
	"slices"
)

var (
	ErrBudgetInvalid          = errors.New("invalid protected capacity budget")
	ErrBudgetFull             = errors.New("protected capacity unavailable")
	ErrCapacityNotAllocated   = errors.New("capacity not allocated")
	ErrAmbiguousBudgetProfile = errors.New("ambiguous budget profile")
)

// BudgetAmount counts logical bytes and objects independently. A physical
// qualification and accepted source must be supplied separately; valid arithmetic
// does not establish either one.
type BudgetAmount struct{ Bytes, Objects int64 }

func (a BudgetAmount) nonnegative() bool { return a.Bytes >= 0 && a.Objects >= 0 }
func (a BudgetAmount) positive() bool    { return a.Bytes > 0 && a.Objects > 0 }
func (a BudgetAmount) contains(b BudgetAmount) bool {
	return b.nonnegative() && a.Bytes >= b.Bytes && a.Objects >= b.Objects
}
func (a BudgetAmount) add(b BudgetAmount) (BudgetAmount, bool) {
	if !a.nonnegative() || !b.nonnegative() || a.Bytes > math.MaxInt64-b.Bytes || a.Objects > math.MaxInt64-b.Objects {
		return BudgetAmount{}, false
	}
	return BudgetAmount{a.Bytes + b.Bytes, a.Objects + b.Objects}, true
}
func (a BudgetAmount) multiply(n int64) (BudgetAmount, bool) {
	if n < 0 || !a.nonnegative() || n != 0 && (a.Bytes > math.MaxInt64/n || a.Objects > math.MaxInt64/n) {
		return BudgetAmount{}, false
	}
	return BudgetAmount{a.Bytes * n, a.Objects * n}, true
}
func (a BudgetAmount) subtract(b BudgetAmount) (BudgetAmount, bool) {
	if !a.contains(b) {
		return BudgetAmount{}, false
	}
	return BudgetAmount{a.Bytes - b.Bytes, a.Objects - b.Objects}, true
}

// PoolBudgetInput and PolicyBudgetInput are compiler inputs after source
// decoding. They carry no observation, grant, allocation ID or caller identity.
// Policy names only join administrator declarations within that one snapshot.
type PoolBudgetInput struct {
	Name                            string
	Capacity, Safety, System, Burst BudgetAmount
	Slots                           []ProtectedSlotInput
}
type ProtectedSlotInput struct {
	Policy    string
	Workloads int64
	Protected BudgetAmount
}
type PolicyBudgetInput struct {
	Name, Pool, Cluster      string
	Protected, Hard, Context BudgetAmount
	NamespaceMaximum         BudgetAmount
	NamespaceAccounts        int64
}

// CompiledPoolBudget is immutable outside this package. The reconciler adds
// independently accepted source/qualification and exact workload facts before
// it can ask the SQL producer to reserve any of these amounts.
type CompiledPoolBudget struct {
	name                                       string
	capacity, safety, system, burst, protected BudgetAmount
	slots                                      int64
	policies                                   map[string]compiledPolicyBudget
	clusters                                   map[string]compiledClusterBudget
}
type compiledPolicyBudget struct {
	input PolicyBudgetInput
	slots int64
}
type compiledClusterBudget struct {
	protected BudgetAmount
	slots     int64
}

func CompileProtectedPool(p PoolBudgetInput, policies []PolicyBudgetInput) (CompiledPoolBudget, error) {
	var out CompiledPoolBudget
	if p.Name == "" || len(p.Slots) < 1 || len(p.Slots) > 64 || len(policies) < 1 || len(policies) > 64 || !p.Capacity.positive() || !p.Safety.positive() || !p.System.positive() || !p.Burst.positive() {
		return out, ErrBudgetInvalid
	}
	out = CompiledPoolBudget{name: p.Name, capacity: p.Capacity, safety: p.Safety, system: p.System, burst: p.Burst, policies: map[string]compiledPolicyBudget{}, clusters: map[string]compiledClusterBudget{}}
	byName := map[string]PolicyBudgetInput{}
	for _, b := range policies {
		if b.Name == "" || b.Pool != p.Name || b.Cluster == "" || !b.Protected.positive() || !b.Hard.contains(b.Protected) || !b.Context.positive() || !b.Protected.contains(b.Context) || b.NamespaceAccounts < 1 || b.NamespaceAccounts > 10000 || !b.NamespaceMaximum.contains(b.Protected) {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		if _, exists := byName[b.Name]; exists {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		byName[b.Name] = b
	}
	for _, slot := range p.Slots {
		b, found := byName[slot.Policy]
		if !found || slot.Workloads < 1 || slot.Workloads > 10000 || slot.Protected != b.Protected {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		if _, exists := out.policies[slot.Policy]; exists {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		total, ok := slot.Protected.multiply(slot.Workloads)
		if !ok {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		out.protected, ok = out.protected.add(total)
		if !ok {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		cluster := out.clusters[b.Cluster]
		cluster.protected, ok = cluster.protected.add(total)
		if !ok {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
		cluster.slots += slot.Workloads
		out.slots += slot.Workloads
		out.clusters[b.Cluster] = cluster
		out.policies[slot.Policy] = compiledPolicyBudget{b, slot.Workloads}
	}
	if len(out.policies) != len(byName) {
		return CompiledPoolBudget{}, ErrBudgetInvalid
	}
	total := out.protected
	for _, slice := range []BudgetAmount{p.Burst, p.System, p.Safety} {
		var ok bool
		total, ok = total.add(slice)
		if !ok {
			return CompiledPoolBudget{}, ErrBudgetInvalid
		}
	}
	if !p.Capacity.contains(total) {
		return CompiledPoolBudget{}, ErrBudgetFull
	}
	return out, nil
}
func (p CompiledPoolBudget) Protected() BudgetAmount { return p.protected }
func (p CompiledPoolBudget) AccountSlots() int64     { return p.slots }
func (p CompiledPoolBudget) PolicyNames() []string {
	out := make([]string, 0, len(p.policies))
	for name := range p.policies {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// ClusterCeiling is an intersected upper bound. Every burst use also charges
// the one shared pool; this function never creates a separate burst per cluster.
func (p CompiledPoolBudget) ClusterCeiling(cluster string) (BudgetAmount, int64, error) {
	c, ok := p.clusters[cluster]
	if !ok {
		return BudgetAmount{}, 0, ErrCapacityNotAllocated
	}
	limit, ok := c.protected.add(p.burst)
	if !ok {
		return BudgetAmount{}, 0, ErrBudgetInvalid
	}
	return limit, c.slots, nil
}

// CheckParentAdmission preserves every child's unused protected commitment.
// protectedUse is only the admitted child's own increment within its remaining
// protected slice. The SQL adapter derives it from the locked child, never from
// a public request. charged includes retained and uncertain reservations.
func CheckParentAdmission(limit, committedProtected, usedProtected, charged, request, protectedUse BudgetAmount) error {
	if !limit.nonnegative() || !committedProtected.contains(usedProtected) || !charged.contains(usedProtected) || !request.contains(protectedUse) {
		return ErrBudgetInvalid
	}
	remaining, _ := committedProtected.subtract(usedProtected)
	if !remaining.contains(protectedUse) {
		return ErrBudgetInvalid
	}
	total, ok := charged.add(remaining)
	if !ok {
		return ErrBudgetInvalid
	}
	burst, _ := request.subtract(protectedUse)
	total, ok = total.add(burst)
	if !ok {
		return ErrBudgetInvalid
	}
	if !limit.contains(total) {
		return ErrBudgetFull
	}
	return nil
}

// CheckWorkloadAdmission intersects the hard cap with the protected context
// reserve even when all unused shared burst is otherwise available. Non-context
// work cannot borrow context at either its protected or hard ceiling.
func CheckWorkloadAdmission(hard, contextReserve, contextCharged, otherCharged, request BudgetAmount, isContext bool) error {
	if !hard.contains(contextReserve) || !contextCharged.nonnegative() || !otherCharged.nonnegative() || !request.nonnegative() {
		return ErrBudgetInvalid
	}
	total, ok := contextCharged.add(otherCharged)
	if !ok {
		return ErrBudgetInvalid
	}
	total, ok = total.add(request)
	if !ok {
		return ErrBudgetInvalid
	}
	if !hard.contains(total) {
		return ErrBudgetFull
	}
	if !isContext {
		limit, _ := hard.subtract(contextReserve)
		used, ok := otherCharged.add(request)
		if !ok {
			return ErrBudgetInvalid
		}
		if !limit.contains(used) {
			return ErrBudgetFull
		}
	}
	return nil
}
