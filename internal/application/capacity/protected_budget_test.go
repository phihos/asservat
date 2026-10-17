package capacity

import (
	"errors"
	"math"
	"testing"
)

func protectedBudgetFixture() (PoolBudgetInput, []PolicyBudgetInput) {
	return PoolBudgetInput{Name: "store", Capacity: BudgetAmount{128, 128}, Safety: BudgetAmount{16, 16}, System: BudgetAmount{8, 8}, Burst: BudgetAmount{40, 40}, Slots: []ProtectedSlotInput{{Policy: "apps", Workloads: 4, Protected: BudgetAmount{16, 16}}}}, []PolicyBudgetInput{{Name: "apps", Pool: "store", Cluster: "cluster", Protected: BudgetAmount{16, 16}, Hard: BudgetAmount{32, 32}, Context: BudgetAmount{1, 1}, NamespaceMaximum: BudgetAmount{104, 104}, NamespaceAccounts: 4}}
}
func TestProtectedPoolCommitsAllSlotsBeforeEnrollment(t *testing.T) {
	p, b := protectedBudgetFixture()
	compiled, e := CompileProtectedPool(p, b)
	if e != nil || compiled.Protected() != (BudgetAmount{64, 64}) || compiled.AccountSlots() != 4 {
		t.Fatal("complete protected declaration", e)
	}
	ceiling, slots, e := compiled.ClusterCeiling("cluster")
	if e != nil || ceiling != (BudgetAmount{104, 104}) || slots != 4 {
		t.Fatal("cluster envelope", e)
	}
	p.Slots[0].Workloads = 5
	if _, e = CompileProtectedPool(p, b); !errors.Is(e, ErrBudgetFull) {
		t.Fatal("overcommitted unused slot", e)
	}
	// Returned names and caller-owned input slices cannot mutate a compiled plan.
	names := compiled.PolicyNames()
	names[0] = "replacement"
	b[0].Protected = BudgetAmount{1, 1}
	if compiled.PolicyNames()[0] != "apps" || compiled.Protected() != (BudgetAmount{64, 64}) {
		t.Fatal("mutable compiled plan")
	}
}
func TestProtectedPoolRejectsSchemaLegalMultiplicationOverflow(t *testing.T) {
	p, b := protectedBudgetFixture()
	p.Capacity = BudgetAmount{math.MaxInt64, math.MaxInt64}
	p.Slots = nil
	b = nil
	for i := 0; i < 64; i++ {
		name := string(rune('A' + i))
		amount := BudgetAmount{1 << 50, 1_000_000_000}
		p.Slots = append(p.Slots, ProtectedSlotInput{Policy: name, Workloads: 10000, Protected: amount})
		b = append(b, PolicyBudgetInput{Name: name, Pool: p.Name, Cluster: "cluster", Protected: amount, Hard: amount, Context: BudgetAmount{1, 1}, NamespaceMaximum: amount, NamespaceAccounts: 10000})
	}
	if _, e := CompileProtectedPool(p, b); !errors.Is(e, ErrBudgetInvalid) {
		t.Fatal("overflow must not become spare capacity", e)
	}
}
func TestProtectedPoolRejectsMismatchAndUnlistedPolicies(t *testing.T) {
	for _, mutate := range []func(*PoolBudgetInput, *[]PolicyBudgetInput){
		func(p *PoolBudgetInput, _ *[]PolicyBudgetInput) { p.Slots[0].Protected.Objects++ },
		func(_ *PoolBudgetInput, b *[]PolicyBudgetInput) {
			copy := (*b)[0]
			copy.Name = "extra"
			*b = append(*b, copy)
		},
		func(p *PoolBudgetInput, _ *[]PolicyBudgetInput) { p.Slots = append(p.Slots, p.Slots[0]) },
		func(_ *PoolBudgetInput, b *[]PolicyBudgetInput) { (*b)[0].Context.Bytes = 17 },
		func(_ *PoolBudgetInput, b *[]PolicyBudgetInput) { (*b)[0].NamespaceMaximum.Objects = 15 },
	} {
		p, b := protectedBudgetFixture()
		mutate(&p, &b)
		if _, e := CompileProtectedPool(p, b); !errors.Is(e, ErrBudgetInvalid) {
			t.Fatal("declaration mismatch accepted", e)
		}
	}
}
func TestParentDoesNotLendAnotherWorkloadsUnusedProtection(t *testing.T) {
	// A used its16 plus all40 burst; B/C/D's48 remains protected. B's own
	// protected admission fits despite A's load; another A burst byte does not.
	limit := BudgetAmount{104, 104}
	commitment := BudgetAmount{64, 64}
	used := BudgetAmount{16, 16}
	charged := BudgetAmount{56, 56}
	if e := CheckParentAdmission(limit, commitment, used, charged, BudgetAmount{16, 16}, BudgetAmount{16, 16}); e != nil {
		t.Fatal("B lost its protected allocation", e)
	}
	if e := CheckParentAdmission(limit, commitment, used, charged, BudgetAmount{1, 1}, BudgetAmount{}); !errors.Is(e, ErrBudgetFull) {
		t.Fatal("A borrowed B capacity", e)
	}
	if e := CheckParentAdmission(BudgetAmount{104, 103}, commitment, used, charged, BudgetAmount{1, 1}, BudgetAmount{1, 1}); !errors.Is(e, ErrBudgetFull) {
		t.Fatal("object parent checked independently", e)
	}
}
func TestContextReserveSurvivesWorkloadHardCeiling(t *testing.T) {
	hard := BudgetAmount{32, 32}
	reserve := BudgetAmount{1, 1}
	if e := CheckWorkloadAdmission(hard, reserve, BudgetAmount{}, BudgetAmount{31, 31}, BudgetAmount{1, 1}, false); !errors.Is(e, ErrBudgetFull) {
		t.Fatal("expensive work borrowed hard context reserve", e)
	}
	if e := CheckWorkloadAdmission(hard, reserve, BudgetAmount{}, BudgetAmount{31, 31}, BudgetAmount{1, 1}, true); e != nil {
		t.Fatal("reserved context refused", e)
	}
	if e := CheckWorkloadAdmission(hard, reserve, BudgetAmount{1, 1}, BudgetAmount{31, 31}, BudgetAmount{1, 1}, true); !errors.Is(e, ErrBudgetFull) {
		t.Fatal("context escaped hard cap", e)
	}
}
