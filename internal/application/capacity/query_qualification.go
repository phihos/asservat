package capacity

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const ContextQueryQualificationFormat = "protected-context-query-qualification/v1"
const ContextQueryHistoryLayout = "context-query-worker-history/v1"

// QueryProcessEnvelope is actual independently qualified dedicated capacity,
// additional to capture/download capacity. All root slots are charged, including
// expired or uncertain workers; this first finite profile never replenishes.
type QueryProcessEnvelope struct {
	CPUMilli, MemoryBytes, EphemeralStorageBytes, WorkerTransientBytes, HubTransientBytes int64
	ProviderConcurrency, AuthenticationConcurrency                                        int64
}
type QueryEnvelope struct {
	value.ContextQueryCost
	QueryProcessEnvelope
}

// QueryDeploymentPin identifies the independently protected and measured
// deployment, including enforced resource/concurrency configuration. A unique
// CapacityID prevents double pledge; it does not prove physical capacity.
type QueryDeploymentPin struct {
	Role, ClusterID, NamespaceUID, WorkloadUID, Image string
	Configuration                                     identity.Revision
	ProtectionDigest, EnforcedLimitsDigest            artifact.Digest
	Limits                                            QueryProcessEnvelope
}

type QueryNativeQualification struct {
	Revision                          identity.Revision
	Format, RunID                     string
	ReportDigest, SourceTree          artifact.Digest
	ProfileDigest                     artifact.Digest
	Worker, Hub, KeyService, Provider QueryDeploymentPin
	Combined                          QueryProcessEnvelope
}

// These are accepted measurement quantities for the complete finite SQL,
// backup, WAL and control graph, not estimates inferred from wire byte limits.
// The original protected installer pins the exact report and declaration. The
// producer ALSO requires the concrete current deployment guard; this DTO does
// not authenticate a report or establish native enforcement by itself.
type QueryHistoryQualification struct {
	Layout                                                   string
	Revision                                                 identity.Revision
	FixedBytes, PrincipalBytes, AllocationBytes, RowBytes    int64
	FixedQueryRows, InvocationRows, ControlRows              int64
	TransitionWALBytes, BackupCopies, WALCopies              int64
	AuditCipherBytes, AuthenticationPerCall, ProviderPerCall int64
	AuthenticationPerControl, ProviderPerControl             int64
	AuthenticationPerSource, ProviderPerSource               int64
	BackupHorizon, RetirementCleanup                         time.Duration
}

type ContextQueryQualification struct {
	Format, CapacityID                                                                  string
	Profile                                                                             value.ContextQueryResourceProfile
	Native                                                                              QueryNativeQualification
	History                                                                             QueryHistoryQualification
	Envelope                                                                            QueryEnvelope
	RootQueries, PrincipalQueries, PrincipalAccounts, WorkloadAccounts, WorkloadQueries int64
	SourceTransitionLimit                                                               int64
	Admission                                                                           time.Duration
	PolicyRevision                                                                      identity.Revision
	PermittedRegions                                                                    []string
	Clients                                                                             []value.ContextProjectionClient
}

func queryPositive(v int64) bool { return v > 0 && v <= 1<<60 }
func (q QueryProcessEnvelope) values() []int64 {
	return []int64{q.CPUMilli, q.MemoryBytes, q.EphemeralStorageBytes, q.WorkerTransientBytes, q.HubTransientBytes, q.ProviderConcurrency, q.AuthenticationConcurrency}
}
func (q QueryNativeQualification) valid(p value.ContextQueryResourceProfile) bool {
	if q.Format != "context-query-native-qualification/v1" || q.Revision != p.Qualification || !q.Revision.Valid() || !identity.Text(q.RunID, 128) || q.ReportDigest == (artifact.Digest{}) || q.SourceTree == (artifact.Digest{}) {
		return false
	}
	body, e := json.Marshal(p)
	if e != nil || q.ProfileDigest != sha256.Sum256(body) {
		return false
	}
	var totals [7]int64
	for i, pin := range []QueryDeploymentPin{q.Worker, q.Hub, q.KeyService, q.Provider} {
		if pin.Role != []string{"query-worker", "hub", "query-key-service", "query-provider"}[i] || !authorization.UUID(pin.ClusterID) || !identity.Text(pin.NamespaceUID, 64) || !identity.Text(pin.WorkloadUID, 64) || !identity.Text(pin.Image, 512) || !pinnedImage(pin.Image) || !pin.Configuration.Valid() || pin.ProtectionDigest == (artifact.Digest{}) || pin.EnforcedLimitsDigest == (artifact.Digest{}) {
			return false
		}
		for j, n := range pin.Limits.values() {
			var ok bool
			if !queryPositive(n) {
				return false
			}
			totals[j], ok = capacitySum(totals[j], n)
			if !ok {
				return false
			}
		}
		copies, ok := capacitySum(pin.Limits.WorkerTransientBytes, pin.Limits.HubTransientBytes)
		if !ok || copies > pin.Limits.MemoryBytes {
			return false
		}
	}
	if q.Worker.ClusterID != p.Path.AcquisitionClusterID || q.Worker.Configuration != p.Path.WorkerConfiguration || q.Hub.ClusterID != p.Path.HubClusterID || q.Hub.Configuration != p.Path.HubConfiguration {
		return false
	}
	for i, n := range q.Combined.values() {
		if !queryPositive(n) || n != totals[i] {
			return false
		}
	}
	return true
}

func pinnedImage(s string) bool {
	// The accepted source owns the repository name; only immutable sha256
	// content references are eligible. No tag or unresolved deployment name.
	if len(s) < 73 || s[len(s)-72:len(s)-64] != "@sha256:" {
		return false
	}
	for _, c := range s[len(s)-64:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (q ContextQueryQualification) Valid(root RootBackingInput) bool {
	if q.Format != ContextQueryQualificationFormat || !authorization.UUID(q.CapacityID) || !q.Profile.Valid() || q.Profile.PollLimit > 1000000 || q.Profile.ControlTransitionLimit > 1000000 || !q.Native.valid(q.Profile) || !q.PolicyRevision.Valid() || q.Admission < time.Second || q.Admission > time.Duration(root.AdmissionSeconds)*time.Second || q.PermittedRegions == nil || q.Clients == nil {
		return false
	}
	for _, d := range []time.Duration{q.Admission, q.Profile.Worker.Runtime, q.Profile.Worker.CredentialLifetime, q.Profile.Worker.ProviderEffectLifetime, q.Profile.Worker.Cleanup, q.History.BackupHorizon, q.History.RetirementCleanup} {
		if d < time.Microsecond || d > 365*24*time.Hour || d%time.Microsecond != 0 {
			return false
		}
	}
	for _, n := range []int64{q.RootQueries, q.PrincipalQueries, q.PrincipalAccounts, q.WorkloadAccounts, q.WorkloadQueries, q.SourceTransitionLimit} {
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
	p := value.ContextProjectionPolicy{RootID: root.RootID, InstallationID: root.InstallationID, RecoveryEpoch: root.ProcessingEpoch, Revision: q.PolicyRevision, Path: q.Profile.Path, PermittedRegions: q.PermittedRegions, Clients: q.Clients}
	if !p.WellFormed() {
		return false
	}
	h := q.History
	if h.BackupCopies < root.Metadata.BackupCopies || h.WALCopies < root.Metadata.WALCopies || h.BackupHorizon < time.Duration(root.Normal.Policy.BackupHorizonSeconds)*time.Second || h.RetirementCleanup < time.Duration(root.Normal.Policy.CleanupBudgetSeconds)*time.Second {
		return false
	}
	if h.Layout != ContextQueryHistoryLayout || !h.Revision.Valid() || h.BackupCopies < 1 || h.BackupCopies > 64 || h.WALCopies < 1 || h.WALCopies > 64 || h.BackupHorizon <= 0 || h.BackupHorizon > 365*24*time.Hour || h.RetirementCleanup <= 0 || h.RetirementCleanup > 24*time.Hour {
		return false
	}
	for _, n := range []int64{h.FixedBytes, h.PrincipalBytes, h.AllocationBytes, h.RowBytes, h.FixedQueryRows, h.InvocationRows, h.ControlRows, h.TransitionWALBytes, h.AuditCipherBytes, h.AuthenticationPerCall, h.ProviderPerCall, h.AuthenticationPerControl, h.ProviderPerControl, h.AuthenticationPerSource, h.ProviderPerSource} {
		if !queryPositive(n) {
			return false
		}
	}
	need, e := q.required()
	if e != nil || !queryEnvelopeContains(q.Envelope, need) {
		return false
	}
	// The whole dedicated deployment profile is reserved. A surplus in a hub
	// cannot satisfy worker resource limits, and a unique capacity ID alone
	// cannot replace explicit physical or executable-enforced quantities.
	if q.Envelope.QueryProcessEnvelope != q.Native.Combined {
		return false
	}
	for _, pair := range [][2]int64{
		{q.Native.Worker.Limits.CPUMilli, q.Profile.Worker.CPUMilli},
		{q.Native.Worker.Limits.MemoryBytes, q.Profile.Worker.MemoryBytes},
		{q.Native.Worker.Limits.EphemeralStorageBytes, q.Profile.Worker.EphemeralStorageBytes},
		{q.Native.Worker.Limits.WorkerTransientBytes, q.Profile.Worker.WorkerTransientBytes},
		{q.Native.Hub.Limits.HubTransientBytes, q.Profile.Worker.HubTransientBytes},
		{q.Native.Provider.Limits.ProviderConcurrency, q.Profile.Worker.ProviderConcurrency},
	} {
		n, ok := capacityProduct(pair[1], q.RootQueries)
		if !ok || pair[0] < n {
			return false
		}
	}
	for _, pin := range []QueryDeploymentPin{q.Native.Worker, q.Native.Hub, q.Native.KeyService, q.Native.Provider} {
		n, ok := capacityProduct(q.Profile.Worker.AuthenticationConcurrency, q.RootQueries)
		if !ok || pin.Limits.AuthenticationConcurrency < n {
			return false
		}
	}
	for i, n := range q.Envelope.QueryProcessEnvelope.values() {
		if !queryPositive(n) || n > q.Native.Combined.values()[i] {
			return false
		}
	}
	return true
}

func queryEnvelopeContains(have, need QueryEnvelope) bool {
	// Reflection-free JSON field comparison keeps every independent dimension
	// explicit in the SQL-compatible vector, including future added fields.
	a, _ := json.Marshal(have)
	b, _ := json.Marshal(need)
	var x, y map[string]int64
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil || len(x) != len(y) {
		return false
	}
	for k, n := range y {
		if !queryPositive(x[k]) || x[k] < n {
			return false
		}
	}
	return true
}

func (q ContextQueryQualification) required() (QueryEnvelope, error) {
	var out QueryEnvelope
	p, h := q.Profile, q.History
	// The query-purpose worker layout includes lifecycle, bounded signing and
	// durable inventory observation/control rows. SQL68's 8+poll floor alone
	// cannot back this composition. These are row-count lower bounds, never
	// measured row/index bytes or transaction WAL costs.
	calls, ok := capacitySum(1, p.PollLimit)
	if !ok {
		return out, ErrBudgetInvalid
	}
	minimumFixed, ok := capacitySum(8, p.Cost.SigningAttempts)
	if !ok || h.FixedQueryRows < minimumFixed {
		return out, ErrBudgetInvalid
	}
	invocationRows, ok := capacityProduct(calls, h.InvocationRows)
	if !ok {
		return out, ErrBudgetInvalid
	}
	controlRows, ok := capacityProduct(p.ControlTransitionLimit, h.ControlRows)
	if !ok {
		return out, ErrBudgetInvalid
	}
	rows, ok := capacitySum(h.FixedQueryRows, invocationRows, controlRows)
	if !ok {
		return out, ErrBudgetInvalid
	}
	if p.Cost.SQLRows < rows {
		return out, ErrBudgetInvalid
	}
	minProduct := func(have int64, factors ...int64) bool { n, ok := capacityProduct(factors...); return ok && have >= n }
	invocationAudits, ok := capacityProduct(2, calls)
	if !ok {
		return out, ErrBudgetInvalid
	}
	allAudits, ok := capacitySum(invocationAudits, 1, p.Cost.SigningAttempts)
	if !ok || p.Cost.AuditObjects < allAudits {
		return out, ErrBudgetInvalid
	}
	if !minProduct(p.Cost.SQLBytes, p.Cost.SQLRows, h.RowBytes) || !minProduct(p.Cost.BackupBytes, p.Cost.SQLBytes, h.BackupCopies) || !minProduct(p.Cost.WALBytes, p.ControlTransitionLimit, h.TransitionWALBytes, h.WALCopies) {
		return out, ErrBudgetInvalid
	}
	authCalls, ok := capacityProduct(calls, h.AuthenticationPerCall)
	if !ok {
		return out, ErrBudgetInvalid
	}
	authControl, ok := capacityProduct(p.ControlTransitionLimit, h.AuthenticationPerControl)
	if !ok {
		return out, ErrBudgetInvalid
	}
	providers, ok := capacityProduct(calls, h.ProviderPerCall)
	if !ok {
		return out, ErrBudgetInvalid
	}
	providerControl, ok := capacityProduct(p.ControlTransitionLimit, h.ProviderPerControl)
	if !ok {
		return out, ErrBudgetInvalid
	}
	auth, ok := capacitySum(authCalls, authControl)
	if !ok || p.Cost.AuthenticationRequests < auth {
		return out, ErrBudgetInvalid
	}
	providers, ok = capacitySum(providers, providerControl, p.Cost.UnwrapAttempts, p.Cost.SigningAttempts)
	if !ok || p.Cost.ProviderRequests < providers {
		return out, ErrBudgetInvalid
	}
	b, _ := json.Marshal(p.Cost)
	var cost map[string]int64
	if json.Unmarshal(b, &cost) != nil {
		return out, ErrBudgetInvalid
	}
	for k, n := range cost {
		v, ok := capacityProduct(n, q.RootQueries)
		if !ok {
			return out, ErrBudgetInvalid
		}
		cost[k] = v
	}
	b, _ = json.Marshal(cost)
	if json.Unmarshal(b, &out.ContextQueryCost) != nil {
		return out, ErrBudgetInvalid
	}
	// Fixed/account history consumes residual capacity in addition to each
	// precharged query's own history and copies.
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
	// Source observations, fixed acceptance and principal/workload insertion
	// are separate transactions. One terminal negative is reserved even when
	// the positive observation allowance is exhausted.
	transitions, ok := capacitySum(2, q.PrincipalAccounts, q.WorkloadAccounts, q.SourceTransitionLimit)
	if !ok {
		return out, ErrBudgetInvalid
	}
	fixedWAL, ok := capacityProduct(transitions, h.TransitionWALBytes, h.WALCopies)
	if !ok || !capacityAddTo(&out.WALBytes, fixedWAL) {
		return out, ErrBudgetInvalid
	}
	for _, charge := range []struct {
		target    *int64
		perSource int64
	}{{&out.AuthenticationRequests, h.AuthenticationPerSource}, {&out.ProviderRequests, h.ProviderPerSource}} {
		requests, ok := capacityProduct(q.SourceTransitionLimit+1, charge.perSource)
		if !ok || !capacityAddTo(charge.target, requests) {
			return out, ErrBudgetInvalid
		}
	}
	for i, n := range []int64{p.Worker.CPUMilli, p.Worker.MemoryBytes, p.Worker.EphemeralStorageBytes, p.Worker.WorkerTransientBytes, p.Worker.HubTransientBytes, p.Worker.ProviderConcurrency, p.Worker.AuthenticationConcurrency} {
		v, ok := capacityProduct(n, q.RootQueries)
		if !ok {
			return out, ErrBudgetInvalid
		}
		*[]*int64{&out.CPUMilli, &out.MemoryBytes, &out.EphemeralStorageBytes, &out.WorkerTransientBytes, &out.HubTransientBytes, &out.ProviderConcurrency, &out.AuthenticationConcurrency}[i] = v
	}
	return out, nil
}

func capacitySum(v ...int64) (int64, bool) {
	var n int64
	for _, x := range v {
		if !capacityAddTo(&n, x) {
			return 0, false
		}
	}
	return n, true
}

type QueryBackingPlan struct {
	RootID, InstallationID, AcceptanceID, RootAttemptID string
	RootPlanDigest, SetupInputDigest                    artifact.Digest
	Qualification                                       ContextQueryQualification
	Reservation                                         RootBackingEnvelope
	HardUntil, EffectsUntil, CleanupUntil, RetireBy     time.Time
}

// CompileQueryBacking only computes the proposal. Acceptance additionally
// requires the exact installed setup receipt/qualification and current native
// deployment/source proof, then independent SQL compilation under root locks.
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
	// Deep copy slices so mutation of installer-owned buffers cannot change a
	// compiled acceptance after validation or while it waits for SQL.
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
