package capacity

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic declarations exercise compiler arithmetic only. They are not native
// reports, protected acceptance or a qualified installed resource profile.
func queryCapacityFixture(t *testing.T) (CapacityQualification, ProtectedPoolPlan, RootBackingPlan, RootConfiguration) {
	t.Helper()
	q, pool := capacityQualificationFixture()
	id := q.ID
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose}
	p := value.ContextQueryResourceProfile{ID: id, Source: rev, Qualification: rev, Path: path, Lifetime: 10 * time.Second, PollLimit: 4, ControlTransitionLimit: 32,
		Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
		Cost:   value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 8 << 20, StructuredBytes: 48 << 10, WireBytes: 128 << 10, UnwrapAttempts: 6, ProviderRequests: 100, AuthenticationRequests: 100, SigningAttempts: 2, AuditObjects: 14, SQLRows: 47, SQLBytes: 1 << 20, WALBytes: 8 << 20, BackupBytes: 2 << 20}}
	h := QueryHistoryQualification{Layout: ContextQueryHistoryLayout, Revision: rev, FixedBytes: 1 << 20, PrincipalBytes: 4096, AllocationBytes: 4096, RowBytes: 4096, FixedQueryRows: 10, InvocationRows: 1, ControlRows: 1, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2, AuditCipherBytes: 64 << 10, BackupHorizon: time.Hour, RetirementCleanup: time.Minute}
	x := ContextQueryQualification{Format: ContextQueryQualificationFormat, CapacityID: "30000000-0000-4000-8000-000000000019", Profile: p, History: h, RootQueries: 4, PrincipalQueries: 2, PrincipalAccounts: 4, WorkloadAccounts: 2, WorkloadQueries: 2, Admission: time.Hour}
	var e error
	x.Envelope, e = x.Required()
	if e != nil {
		t.Fatal(e)
	}
	q.ContextQuery = &x
	base, e := CompileQualifiedRootBacking(q, pool)
	if e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	at := n.Add(time.Millisecond)
	root := RootConfiguration{Format: RootConfigurationFormat, RootID: id, AttemptID: "30000000-0000-4000-8000-000000000020", PlanDigest: base.digest, Revision: 1, InitialObservedAt: n, InitialUntil: n.Add(5 * time.Second), RevisionObservedAt: n, RevisionUntil: n.Add(5 * time.Second), PlannedUntil: n.Add(time.Hour), ReservedAt: at, CaptureBackedAt: &at, ReadyAt: &at}
	return q, pool, base, root
}

func TestQueryCapacityReservesResidualAndOriginalHorizons(t *testing.T) {
	q, pool, base, root := queryCapacityFixture(t)
	plan, e := CompileQueryBacking(q, root, base, pool, artifact.Digest{6}, q.ID)
	if e != nil {
		t.Fatal(e)
	}
	if !plan.HardUntil.Equal(root.InitialObservedAt.Add(time.Hour)) || !plan.EffectsUntil.Equal(plan.HardUntil.Add(2*time.Minute)) || !plan.CleanupUntil.Equal(plan.EffectsUntil.Add(time.Minute)) || !plan.RetireBy.Equal(plan.CleanupUntil.Add(2*time.Hour+time.Minute)) {
		t.Fatal("lost independent original horizons")
	}
	if plan.Reservation.SQLBytes != q.ContextQuery.Envelope.SQLBytes || plan.Reservation.SystemObjects.Bytes != q.ContextQuery.Envelope.AuditObjects*q.ContextQuery.History.AuditCipherBytes {
		t.Fatal("missing additive reservation")
	}
	// A subsequent root revision cannot move the original query hard cutoff.
	q, pool, base, root = queryCapacityFixture(t)
	original := root.InitialObservedAt
	root.Revision = 2
	root.PreviousDigest = artifact.Digest{9}
	root.RevisionObservedAt = original.Add(time.Minute)
	root.RevisionUntil = root.RevisionObservedAt.Add(5 * time.Second)
	root.ReservedAt = root.RevisionObservedAt
	at := root.ReservedAt
	root.CaptureBackedAt = &at
	root.ReadyAt = &at
	root.PlannedUntil = root.PlannedUntil.Add(time.Minute)
	plan, e = CompileQueryBacking(q, root, base, pool, artifact.Digest{6}, q.ID)
	if e != nil || !plan.HardUntil.Equal(original.Add(time.Hour)) {
		t.Fatal("root renewal replenished query lifetime", e)
	}
}

func TestQueryCapacityEveryResidualDimensionIsIndependent(t *testing.T) {
	for _, name := range []string{"sql", "backup", "wal", "key", "system-bytes", "system-objects", "physical-system"} {
		t.Run(name, func(t *testing.T) {
			q, pool, base, root := queryCapacityFixture(t)
			totals := base.Totals()
			// Recompile the base because protected input changes must retain their
			// own exact root plan identity. Base capacity still fits; query does not.
			switch name {
			case "sql":
				q.RootBacking.Envelope.SQLBytes = totals.SQLBytes
			case "backup":
				q.RootBacking.Envelope.BackupBytes = totals.BackupBytes
			case "wal":
				q.RootBacking.Envelope.WALBytes = totals.WALBytes
			case "key":
				q.RootBacking.Envelope.KeyAttempts = totals.KeyAttempts
			case "system-bytes":
				q.RootBacking.Envelope.SystemObjects.Bytes = totals.SystemObjects.Bytes
			case "system-objects":
				q.RootBacking.Envelope.SystemObjects.Objects = totals.SystemObjects.Objects
			case "physical-system":
				pool.System = totals.SystemObjects
			}
			var e error
			base, e = CompileQualifiedRootBacking(q, pool)
			if e != nil {
				t.Fatal("base no longer fits", e)
			}
			root.PlanDigest = base.digest
			if _, e = CompileQueryBacking(q, root, base, pool, artifact.Digest{6}, q.ID); e != ErrBudgetFull {
				t.Fatal("query borrowed already reserved capacity", e)
			}
		})
	}
}

func TestQueryCapacityRejectsUnqualifiedOrUnfundedProfile(t *testing.T) {
	changes := map[string]func(*ContextQueryQualification){
		"legacy-layout":               func(q *ContextQueryQualification) { q.Format = "protected-context-query-qualification/v1" },
		"root-target":                 func(q *ContextQueryQualification) { q.Profile.Path.TargetClusterID = q.Profile.ID },
		"workload-overcommit":         func(q *ContextQueryQualification) { q.WorkloadQueries++ },
		"principal-overcommit":        func(q *ContextQueryQualification) { q.PrincipalQueries = q.RootQueries + 1 },
		"missing-worker-intent-audit": func(q *ContextQueryQualification) { q.Profile.Cost.AuditObjects-- },
		"missing-identity-wal": func(q *ContextQueryQualification) {
			q.Profile.Cost.WALBytes = q.Profile.ControlTransitionLimit * q.History.TransitionWALBytes * q.History.WALCopies
		},
		"history-rows":    func(q *ContextQueryQualification) { q.Profile.Cost.SQLRows = 12 },
		"unfunded-backup": func(q *ContextQueryQualification) { q.Envelope.BackupBytes-- },
		"fractional-time": func(q *ContextQueryQualification) { q.Admission += time.Nanosecond },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			q, pool, base, root := queryCapacityFixture(t)
			change(q.ContextQuery)
			if _, err := CompileQueryBacking(q, root, base, pool, artifact.Digest{6}, q.ID); err == nil {
				t.Fatal("invalid shared query budget accepted")
			}
		})
	}
}

func TestQueryCapacityOmittedExtensionPreservesOriginalBytes(t *testing.T) {
	q, _ := capacityQualificationFixture()
	b, e := json.Marshal(q)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(b, []byte("ContextQuery")) {
		t.Fatal("legacy protected input changed")
	}
	var decoded CapacityQualification
	if json.Unmarshal(b, &decoded) != nil || !decoded.Valid() {
		t.Fatal("legacy root lost validity")
	}
}

func TestQueryCapacityHasNoSeparateObservationAllowance(t *testing.T) {
	q, _, _, _ := queryCapacityFixture(t)
	body, err := json.Marshal(q.ContextQuery)
	if err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"Native", "SourceTransitionLimit", "AuthenticationPerSource", "ProviderPerSource", "PermittedRegions"} {
		if bytes.Contains(body, []byte(removed)) {
			t.Fatalf("retained second engine field %s", removed)
		}
	}
}
