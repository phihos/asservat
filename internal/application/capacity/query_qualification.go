package capacity

import (
	"encoding/json"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const ContextQueryQualificationFormat = "shared-installed-context-query/v1"
const ContextQueryHistoryLayout = "shared-context-query-history/v1"

// QueryHistoryQualification declares finite SQL/index/backup/WAL and encrypted
// audit budgets. WAL and history sizes are configured estimates, not measured
// upper bounds on resource usage.
type QueryHistoryQualification struct {
	Layout                                                        string
	Revision                                                      identity.Revision
	FixedBytes, PrincipalBytes, AllocationBytes, RowBytes         int64
	FixedQueryRows, InvocationRows, ControlRows                   int64
	TransitionWALBytes, BackupCopies, WALCopies, AuditCipherBytes int64
	BackupHorizon, RetirementCleanup                              time.Duration
}

// ContextQueryQualification adds only logical obligations to the original
// installed root. Profile.Path is deliberately unselected: current accepted
// placement and the exact charged workload supply it for each request. Physical
// workers, hub delivery and key/provider slots are shared with native downloads.
type ContextQueryQualification struct {
	Format, CapacityID                                                                  string
	Profile                                                                             value.ContextQueryResourceProfile
	History                                                                             QueryHistoryQualification
	Envelope                                                                            value.ContextQueryCost
	RootQueries, PrincipalQueries, PrincipalAccounts, WorkloadAccounts, WorkloadQueries int64
	Admission                                                                           time.Duration
}

func queryPositive(n int64) bool { return n > 0 && n <= 1<<60 }

func capacitySum(values ...int64) (int64, bool) {
	var total int64
	for _, n := range values {
		if !capacityAddTo(&total, n) {
			return 0, false
		}
	}
	return total, true
}

func (q ContextQueryQualification) Valid(root RootBackingInput) bool {
	p, h := q.Profile, q.History
	if q.Format != ContextQueryQualificationFormat || !authorization.UUID(q.CapacityID) || !p.SharedBudgetValid() ||
		q.Admission < time.Second || q.Admission > time.Duration(root.AdmissionSeconds)*time.Second ||
		h.Layout != ContextQueryHistoryLayout || !h.Revision.Valid() {
		return false
	}
	for _, d := range []time.Duration{q.Admission, p.Lifetime, p.Worker.Runtime, p.Worker.CredentialLifetime, p.Worker.ProviderEffectLifetime, p.Worker.Cleanup, h.BackupHorizon, h.RetirementCleanup} {
		if d < time.Microsecond || d > 365*24*time.Hour || d%time.Microsecond != 0 {
			return false
		}
	}
	for _, n := range []int64{q.RootQueries, q.PrincipalQueries, q.PrincipalAccounts, q.WorkloadAccounts, q.WorkloadQueries} {
		if n < 1 || n > 1000000 {
			return false
		}
	}
	if q.PrincipalQueries > q.RootQueries || q.PrincipalAccounts > q.RootQueries || q.WorkloadAccounts > root.Accounts {
		return false
	}
	if n, ok := capacityProduct(q.WorkloadAccounts, q.WorkloadQueries); !ok || n > q.RootQueries {
		return false
	}
	if h.BackupCopies < root.Metadata.BackupCopies || h.BackupCopies > 64 || h.WALCopies < root.Metadata.WALCopies || h.WALCopies > 64 ||
		h.BackupHorizon < time.Duration(root.Normal.Policy.BackupHorizonSeconds)*time.Second ||
		h.RetirementCleanup < time.Duration(root.Normal.Policy.CleanupBudgetSeconds)*time.Second || h.RetirementCleanup > 24*time.Hour {
		return false
	}
	for _, n := range []int64{h.FixedBytes, h.PrincipalBytes, h.AllocationBytes, h.RowBytes, h.FixedQueryRows, h.InvocationRows, h.ControlRows, h.TransitionWALBytes, h.AuditCipherBytes} {
		if !queryPositive(n) {
			return false
		}
	}
	need, e := q.Required()
	return e == nil && queryCostContains(q.Envelope, need)
}

func queryCostContains(have, need value.ContextQueryCost) bool {
	a, _ := json.Marshal(have)
	b, _ := json.Marshal(need)
	var x, y map[string]int64
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	for k, n := range y {
		if !queryPositive(x[k]) || x[k] < n {
			return false
		}
	}
	return true
}

// Required computes charged logical bounds, not performance measurements. The
// fixed worker-intent audit and enrollment audit are distinct objects.
func (q ContextQueryQualification) Required() (value.ContextQueryCost, error) {
	var out value.ContextQueryCost
	p, h := q.Profile, q.History
	calls, ok := capacitySum(1, p.PollLimit)
	if !ok {
		return out, ErrBudgetInvalid
	}
	fixed, ok := capacitySum(8, p.Cost.SigningAttempts)
	if !ok || h.FixedQueryRows < fixed {
		return out, ErrBudgetInvalid
	}
	inv, ok := capacityProduct(calls, h.InvocationRows)
	if !ok {
		return out, ErrBudgetInvalid
	}
	ctl, ok := capacityProduct(p.ControlTransitionLimit, h.ControlRows)
	if !ok {
		return out, ErrBudgetInvalid
	}
	rows, ok := capacitySum(h.FixedQueryRows, inv, ctl)
	if !ok || p.Cost.SQLRows < rows {
		return out, ErrBudgetInvalid
	}
	audits, ok := capacityProduct(2, calls)
	if !ok {
		return out, ErrBudgetInvalid
	}
	audits, ok = capacitySum(audits, 2, p.Cost.SigningAttempts)
	if !ok || p.Cost.AuditObjects < audits {
		return out, ErrBudgetInvalid
	}
	// Shared identity rows do not increment the query's control counter:
	// seven worker transitions, two enrollment transitions and four per
	// certificate attempt. Include their configured WAL estimate without
	// adding a runtime counter or treating the estimate as a measured bound.
	certificates, ok := capacityProduct(4, p.Cost.SigningAttempts)
	if !ok {
		return out, ErrBudgetInvalid
	}
	walTransitions, ok := capacitySum(p.ControlTransitionLimit, 9, certificates)
	if !ok {
		return out, ErrBudgetInvalid
	}
	minProduct := func(have int64, factors ...int64) bool { n, ok := capacityProduct(factors...); return ok && have >= n }
	if !minProduct(p.Cost.SQLBytes, p.Cost.SQLRows, h.RowBytes) || !minProduct(p.Cost.BackupBytes, p.Cost.SQLBytes, h.BackupCopies) ||
		!minProduct(p.Cost.WALBytes, walTransitions, h.TransitionWALBytes, h.WALCopies) {
		return out, ErrBudgetInvalid
	}
	auth, ok := capacitySum(calls, p.ControlTransitionLimit, p.Cost.SigningAttempts)
	if !ok || p.Cost.AuthenticationRequests < auth {
		return out, ErrBudgetInvalid
	}
	providers, ok := capacityProduct(2, audits)
	if !ok {
		return out, ErrBudgetInvalid
	}
	providers, ok = capacitySum(providers, p.Cost.UnwrapAttempts, p.Cost.SigningAttempts, p.Cost.ReadBatches)
	if !ok || p.Cost.ProviderRequests < providers {
		return out, ErrBudgetInvalid
	}
	body, _ := json.Marshal(p.Cost)
	var costs map[string]int64
	if json.Unmarshal(body, &costs) != nil {
		return out, ErrBudgetInvalid
	}
	for k, n := range costs {
		v, ok := capacityProduct(n, q.RootQueries)
		if !ok {
			return out, ErrBudgetInvalid
		}
		costs[k] = v
	}
	body, _ = json.Marshal(costs)
	if json.Unmarshal(body, &out) != nil {
		return out, ErrBudgetInvalid
	}
	principal, ok := capacityProduct(q.PrincipalAccounts, h.PrincipalBytes)
	if !ok {
		return out, ErrBudgetInvalid
	}
	allocations, ok := capacityProduct(q.WorkloadAccounts, h.AllocationBytes)
	if !ok {
		return out, ErrBudgetInvalid
	}
	extra, ok := capacitySum(h.FixedBytes, principal, allocations)
	if !ok || !capacityAddTo(&out.SQLBytes, extra) {
		return out, ErrBudgetInvalid
	}
	backup, ok := capacityProduct(extra, h.BackupCopies)
	if !ok || !capacityAddTo(&out.BackupBytes, backup) {
		return out, ErrBudgetInvalid
	}
	// One immutable root acceptance and bounded account/allocation inserts.
	// Currentness comes from the existing source producer; no second polling
	// history or claimed native observation is created for query capacity.
	transitions, ok := capacitySum(1, q.PrincipalAccounts, q.WorkloadAccounts)
	if !ok {
		return out, ErrBudgetInvalid
	}
	wal, ok := capacityProduct(transitions, h.TransitionWALBytes, h.WALCopies)
	if !ok || !capacityAddTo(&out.WALBytes, wal) {
		return out, ErrBudgetInvalid
	}
	return out, nil
}

type QueryBackingPlan struct {
	RootID, InstallationID, AcceptanceID, RootAttemptID string
	RootPlanDigest, SetupInputDigest                    artifact.Digest
	Qualification                                       ContextQueryQualification
	Reservation                                         RootBackingEnvelope
	HardUntil, EffectsUntil, CleanupUntil, RetireBy     time.Time
}

// CompileQueryBacking only computes the proposal. Acceptance additionally
// requires the exact installed setup receipt and current existing capacity
// source, then independent SQL compilation under the original root locks.
func CompileQueryBacking(q CapacityQualification, root RootConfiguration, base RootBackingPlan, system ProtectedPoolPlan, setup artifact.Digest, acceptance string) (QueryBackingPlan, error) {
	var out QueryBackingPlan
	if !q.Valid() || q.ContextQuery == nil || !root.Valid() || !authorization.UUID(acceptance) || setup == (artifact.Digest{}) || root.RootID != q.RootBacking.RootID || root.PlanDigest != base.digest || root.ReadyAt == nil || root.ReconciledAt != nil {
		return out, ErrBudgetInvalid
	}
	current, e := CompileQualifiedRootBacking(q, system)
	if e != nil || current.canonical != base.canonical {
		return out, ErrBudgetInvalid
	}
	x := *q.ContextQuery
	// Snapshot the exact accepted declaration before it is retained.
	encoded, _ := json.Marshal(x)
	x = ContextQueryQualification{}
	if json.Unmarshal(encoded, &x) != nil {
		return out, ErrBudgetInvalid
	}
	objects := x.Envelope.AuditObjects
	bytes, ok := capacityProduct(objects, x.History.AuditCipherBytes)
	if !ok {
		return out, ErrBudgetInvalid
	}
	keys, ok := capacitySum(x.Envelope.UnwrapAttempts, x.Envelope.SigningAttempts, x.Envelope.ProviderRequests)
	if !ok {
		return out, ErrBudgetInvalid
	}
	reservation := RootBackingEnvelope{SystemObjects: BudgetAmount{Bytes: bytes, Objects: objects}, SQLBytes: x.Envelope.SQLBytes, BackupBytes: x.Envelope.BackupBytes, WALBytes: x.Envelope.WALBytes, KeyAttempts: keys}
	t := base.Totals()
	limit := q.RootBacking.Envelope
	for _, v := range [][3]int64{{t.SystemObjects.Bytes, reservation.SystemObjects.Bytes, limit.SystemObjects.Bytes}, {t.SystemObjects.Objects, reservation.SystemObjects.Objects, limit.SystemObjects.Objects}, {t.SystemObjects.Bytes, reservation.SystemObjects.Bytes, system.System.Bytes}, {t.SystemObjects.Objects, reservation.SystemObjects.Objects, system.System.Objects}, {t.SQLBytes, reservation.SQLBytes, limit.SQLBytes}, {t.BackupBytes, reservation.BackupBytes, limit.BackupBytes}, {t.WALBytes, reservation.WALBytes, limit.WALBytes}, {t.KeyAttempts, reservation.KeyAttempts, limit.KeyAttempts}} {
		n, ok := capacitySum(v[0], v[1])
		if !ok || n > v[2] {
			return out, ErrBudgetFull
		}
	}
	hard := root.InitialObservedAt.Add(x.Admission)
	if hard.After(root.PlannedUntil) {
		return out, ErrBudgetInvalid
	}
	effect := hard.Add(max(x.Profile.Worker.Runtime, x.Profile.Worker.CredentialLifetime, x.Profile.Worker.ProviderEffectLifetime))
	cleanup := effect.Add(x.Profile.Worker.Cleanup)
	retire := cleanup.Add(2*x.History.BackupHorizon + x.History.RetirementCleanup)
	out = QueryBackingPlan{RootID: root.RootID, InstallationID: q.RootBacking.InstallationID, AcceptanceID: acceptance, RootAttemptID: root.AttemptID, RootPlanDigest: root.PlanDigest, SetupInputDigest: setup, Qualification: x, Reservation: reservation, HardUntil: hard, EffectsUntil: effect, CleanupUntil: cleanup, RetireBy: retire}
	return out, nil
}
