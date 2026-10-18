package analysis

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

// Synthetic accepted backing exercises structural boundaries only; no fixture
// value is an accepted production source or a measured resource qualification.
func queryPlan(a ContextProjectionAuthority) ContextQueryPlan {
	w := ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10,
		ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute,
		ProviderEffectLifetime: time.Minute, Cleanup: time.Minute}
	c := ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * ContextBatchReadWork, StructuredBytes: 2 * ContextResultBytes,
		WireBytes: 2 * ContextWireBytes, UnwrapAttempts: 6, ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2,
		AuditObjects: 20, SQLRows: 20, SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}
	return ContextQueryPlan{AcceptanceID: queryTestID, AccountID: queryTestID, AllocationID: queryTestID, RootID: a.Scope.RootID,
		InstallationID: a.Environment.InstallationID, ClusterID: a.Scope.ClusterID, NamespaceUID: a.Scope.NamespaceUID,
		WorkloadUID: a.Scope.WorkloadUID, AllocationRevision: 1, PoolSource: a.IdentityRevision, PolicySource: a.IdentityRevision, Principal: a.Scope.Principal,
		Profile: ContextQueryResourceProfile{ID: queryTestID, Source: a.IdentityRevision, Qualification: a.IdentityRevision, Path: a.Environment.Path,
			Lifetime: ContextDefaultQueryTime, Worker: w, Cost: c, PollLimit: 4, ControlTransitionLimit: 32},
		ObservedAt: a.CheckedAt, ValidUntil: a.ValidUntil, HardUntil: a.CheckedAt.Add(time.Minute), EffectsUntil: a.CheckedAt.Add(3 * time.Minute),
		CleanupUntil: a.CheckedAt.Add(4 * time.Minute), RetireBy: a.CheckedAt.Add(time.Hour)}
}

func TestQueryKeepsDisclosureAndUncertainEffectHorizonsSeparate(t *testing.T) {
	a := testAuthority()
	p := queryPlan(a)
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, p, a.CheckedAt)
	if err != nil || !q.Valid() {
		t.Fatal("valid query rejected", err)
	}
	if !q.Deadline.Equal(a.CheckedAt.Add(10*time.Second)) || !q.CredentialUntil.Equal(a.CheckedAt.Add(2*time.Minute)) ||
		!q.CleanupUntil.Equal(a.CheckedAt.Add(3*time.Minute)) {
		t.Fatal("effect/cleanup shortened to result lifetime", q)
	}
	if q.Current(a, q.Deadline) {
		t.Fatal("deadline equality permits result")
	}
	if !q.Valid() {
		t.Fatal("historical obligations disappeared at result expiry")
	}
	for name, mutate := range map[string]func(*ContextQuery){
		"renew-result":                       func(q *ContextQuery) { q.Deadline = q.Deadline.Add(time.Second) },
		"renew-worker":                       func(q *ContextQuery) { q.WorkerUntil = q.WorkerUntil.Add(time.Second) },
		"expire-certificate-at-query":        func(q *ContextQuery) { q.CredentialUntil = q.Deadline },
		"expire-provider-at-query":           func(q *ContextQuery) { q.ProviderUntil = q.Deadline },
		"expire-cleanup-at-query":            func(q *ContextQuery) { q.CleanupUntil = q.Deadline },
		"missing-acceptance":                 func(q *ContextQuery) { q.Plan.AcceptanceID = "" },
		"missing-worker-copy":                func(q *ContextQuery) { q.Plan.Profile.Worker.WorkerTransientBytes = 0 },
		"missing-hub-copy":                   func(q *ContextQuery) { q.Plan.Profile.Worker.HubTransientBytes = 0 },
		"missing-provider-concurrency":       func(q *ContextQuery) { q.Plan.Profile.Worker.ProviderConcurrency = 0 },
		"missing-authentication-concurrency": func(q *ContextQuery) { q.Plan.Profile.Worker.AuthenticationConcurrency = 0 },
		"missing-signing":                    func(q *ContextQuery) { q.Plan.Profile.Cost.SigningAttempts = 0 },
		"missing-wal":                        func(q *ContextQuery) { q.Plan.Profile.Cost.WALBytes = 0 },
		"missing-backup":                     func(q *ContextQuery) { q.Plan.Profile.Cost.BackupBytes = 0 },
		"third-batch":                        func(q *ContextQuery) { q.Plan.Profile.Cost.ReadBatches++ },
		"extra-key":                          func(q *ContextQuery) { q.Plan.Profile.Cost.UnwrapAttempts++ },
		"missing-poll-budget":                func(q *ContextQuery) { q.Plan.Profile.PollLimit = 0 },
		"missing-control-budget":             func(q *ContextQuery) { q.Plan.Profile.ControlTransitionLimit = 0 },
		"insufficient-cleanup-backing":       func(q *ContextQuery) { q.Plan.CleanupUntil = q.Plan.EffectsUntil },
	} {
		t.Run(name, func(t *testing.T) {
			v := q
			mutate(&v)
			if v.Valid() {
				t.Fatal("invalid query accepted")
			}
		})
	}
}

func TestQueryFreshRequestCannotResetOriginalBindings(t *testing.T) {
	a := testAuthority()
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, queryPlan(a), a.CheckedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ContextProjectionAuthority){
		func(a *ContextProjectionAuthority) { a.Scope.Version[0]++ },
		func(a *ContextProjectionAuthority) { a.Scope.Selection.LineStart++ },
		func(a *ContextProjectionAuthority) { a.Environment.Path.ID = queryOtherID },
		func(a *ContextProjectionAuthority) { a.Environment.Recovery.IssuerEpoch = queryOtherID },
		func(a *ContextProjectionAuthority) { a.Environment.Recovery.Revision.Generation++ },
		func(a *ContextProjectionAuthority) {
			a.Scope.Principal.ClientID = "new-client"
			a.Environment.Principal = a.Scope.Principal
		},
	} {
		v := a
		mutate(&v)
		if q.Current(v, a.CheckedAt) {
			t.Fatal("new request rebound query")
		}
	}
	copy := q
	copy.CreatedAt = copy.CreatedAt.In(time.FixedZone("equivalent", 3600))
	if !q.Equal(copy) {
		t.Fatal("instant equality lost")
	}
	copy.CleanupUntil = copy.CleanupUntil.Add(time.Second)
	if q.Equal(copy) {
		t.Fatal("immutable cleanup renewal ignored")
	}
}

func TestReadBatchRequiresExactWorkerInvocationAndOriginalBounds(t *testing.T) {
	a := testAuthority()
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, queryPlan(a), a.CheckedAt)
	if err != nil {
		t.Fatal(err)
	}
	w := ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: queryTestID, PodUID: queryTestID, ProcessEpoch: queryTestID,
		Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	r := ContextQueryRequest{Call: ContextQueryCall{ID: queryTestID, RootID: q.Scope.RootID, Tool: "get_file_excerpt", InputFormat: "context-query-input/v1",
		MACVersion: "v1", InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: q.Scope.Principal,
		StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}, OwnerID: queryTestID, HubProcessEpoch: queryTestID}
	b := ContextReadBatch{QueryID: q.ID, ID: queryTestID, OperationID: r.Call.ID, Generation: 1, Worker: w, Request: r,
		StartedAt: a.CheckedAt, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}
	if !b.Current(q, a, a.CheckedAt) {
		t.Fatal("valid batch rejected")
	}
	for _, mutate := range []func(*ContextReadBatch){
		func(b *ContextReadBatch) { b.Worker.ProcessEpoch = "" }, func(b *ContextReadBatch) { b.Worker.WorkerID = queryOtherID },
		func(b *ContextReadBatch) { b.Request.OwnerID = "" }, func(b *ContextReadBatch) { b.Request.Call.PrincipalDigest = artifact.Digest{} },
		func(b *ContextReadBatch) { b.OperationID = queryOtherID }, func(b *ContextReadBatch) { b.Generation = 3 },
		func(b *ContextReadBatch) { b.Until = b.Request.Call.Until.Add(time.Second) }, func(b *ContextReadBatch) { b.CleanupUntil = b.Until },
	} {
		v := b
		mutate(&v)
		if v.Matches(q) {
			t.Fatal("invalid batch binding accepted", v)
		}
	}
}

func TestQuerySQLPrecisionNeverRenewsOriginalBounds(t *testing.T) {
	a := testAuthority()
	actual := a.CheckedAt.Add(789 * time.Nanosecond)
	p := queryPlan(a)
	// Deliberate fractional configured intervals also round down, never up.
	p.Profile.Worker.Runtime += 456 * time.Nanosecond
	p.Profile.Worker.CredentialLifetime += 456 * time.Nanosecond
	p.Profile.Worker.ProviderEffectLifetime += 456 * time.Nanosecond
	p.Profile.Worker.Cleanup += 456 * time.Nanosecond
	p.CleanupUntil = p.CleanupUntil.Add(time.Second)
	q, err := NewContextQuery(queryTestID, queryTestID, queryTestID, a, p, actual)
	if err != nil {
		t.Fatal(err)
	}
	original := []time.Time{actual, actual.Add(p.Profile.Lifetime), actual.Add(p.Profile.Worker.Runtime), actual.Add(p.Profile.Worker.CredentialLifetime), actual.Add(p.Profile.Worker.ProviderEffectLifetime), actual.Add(p.Profile.Worker.CredentialLifetime + p.Profile.Worker.Cleanup)}
	stored := []time.Time{q.CreatedAt, q.Deadline, q.WorkerUntil, q.CredentialUntil, q.ProviderUntil, q.CleanupUntil}
	for i, got := range stored {
		if got.Nanosecond()%1000 != 0 || got.After(original[i]) {
			t.Fatalf("nonconservative SQL time %d: %s > %s", i, got, original[i])
		}
	}
	replay := q
	replay.CreatedAt = replay.CreatedAt.Truncate(time.Microsecond)
	replay.Deadline = replay.Deadline.Truncate(time.Microsecond)
	replay.WorkerUntil = replay.WorkerUntil.Truncate(time.Microsecond)
	replay.CredentialUntil = replay.CredentialUntil.Truncate(time.Microsecond)
	replay.ProviderUntil = replay.ProviderUntil.Truncate(time.Microsecond)
	replay.CleanupUntil = replay.CleanupUntil.Truncate(time.Microsecond)
	if !q.Equal(replay) || !replay.Valid() {
		t.Fatal("SQL scalar replay changed immutable query")
	}
	changed := q
	changed.WorkerUntil = changed.WorkerUntil.Add(time.Nanosecond)
	if changed.Valid() {
		t.Fatal("noncanonical effect bound accepted")
	}
	// Freshness is checked at actual now, not at the earlier floored timestamp.
	a.ValidUntil = a.CheckedAt.Add(500 * time.Nanosecond)
	if _, err = NewContextQuery(queryTestID, queryTestID, queryTestID, a, queryPlan(a), actual); err == nil {
		t.Fatal("rounding revived already expired authority")
	}
}
