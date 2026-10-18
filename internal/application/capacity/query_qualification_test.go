package capacity

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
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
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: id, TargetClusterID: id, StoreID: q.Backends[0].EvidenceStoreID, StorageRegion: "local", AcquisitionClusterID: id, AcquisitionRegion: "local", ConnectorClusterID: id, ConnectorRegion: "local", HubClusterID: id, HubRegion: "local", WorkerConfiguration: rev, HubConfiguration: rev}
	p := value.ContextQueryResourceProfile{ID: id, Source: rev, Qualification: rev, Path: path, Lifetime: 10 * time.Second, PollLimit: 4, ControlTransitionLimit: 32,
		Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
		Cost:   value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 8 << 20, StructuredBytes: 48 << 10, WireBytes: 128 << 10, UnwrapAttempts: 6, ProviderRequests: 100, AuthenticationRequests: 100, SigningAttempts: 2, AuditObjects: 13, SQLRows: 47, SQLBytes: 1 << 20, WALBytes: 4 << 20, BackupBytes: 2 << 20}}
	h := QueryHistoryQualification{Layout: ContextQueryHistoryLayout, Revision: rev, FixedBytes: 1 << 20, PrincipalBytes: 4096, AllocationBytes: 4096, RowBytes: 4096, FixedQueryRows: 10, InvocationRows: 1, ControlRows: 1, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2, AuditCipherBytes: 64 << 10, AuthenticationPerCall: 1, ProviderPerCall: 1, AuthenticationPerControl: 1, ProviderPerControl: 1, AuthenticationPerSource: 1, ProviderPerSource: 1, BackupHorizon: time.Hour, RetirementCleanup: time.Minute}
	x := ContextQueryQualification{Format: ContextQueryQualificationFormat, CapacityID: "30000000-0000-4000-8000-000000000019", Profile: p, History: h, RootQueries: 4, PrincipalQueries: 2, PrincipalAccounts: 4, WorkloadAccounts: 2, WorkloadQueries: 2, SourceTransitionLimit: 128, Admission: time.Hour, PolicyRevision: rev, PermittedRegions: []string{"local"}, Clients: []value.ContextProjectionClient{{Issuer: "issuer", ID: "console", Kind: identity.Human, Purposes: []string{"incident"}}}}
	var e error
	x.Envelope, e = x.required()
	if e != nil {
		t.Fatal(e)
	}
	pin := func(role string) QueryDeploymentPin {
		return QueryDeploymentPin{Role: role, ClusterID: id, NamespaceUID: "namespace", WorkloadUID: role, Image: "image@sha256:" + strings.Repeat("a", 64), Configuration: rev, ProtectionDigest: artifact.Digest{2}, EnforcedLimitsDigest: artifact.Digest{3}, Limits: x.Envelope.QueryProcessEnvelope}
	}
	body, _ := json.Marshal(p)
	x.Native = QueryNativeQualification{Format: "context-query-native-qualification/v1", Revision: rev, RunID: "synthetic-unit-only", ReportDigest: artifact.Digest{4}, SourceTree: artifact.Digest{5}, ProfileDigest: sha256.Sum256(body), Worker: pin("query-worker"), Hub: pin("hub"), KeyService: pin("query-key-service"), Provider: pin("query-provider"), Combined: x.Envelope.QueryProcessEnvelope}
	x.Native.Combined = QueryProcessEnvelope{CPUMilli: x.Envelope.CPUMilli * 4, MemoryBytes: x.Envelope.MemoryBytes * 4, EphemeralStorageBytes: x.Envelope.EphemeralStorageBytes * 4, WorkerTransientBytes: x.Envelope.WorkerTransientBytes * 4, HubTransientBytes: x.Envelope.HubTransientBytes * 4, ProviderConcurrency: x.Envelope.ProviderConcurrency * 4, AuthenticationConcurrency: x.Envelope.AuthenticationConcurrency * 4}
	x.Envelope.QueryProcessEnvelope = x.Native.Combined
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
	q.ContextQuery.Clients[0].Purposes[0] = "mutated"
	if plan.Qualification.Clients[0].Purposes[0] != "incident" {
		t.Fatal("compiled source aliases installer buffer")
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
	for _, name := range []string{"missing", "worker-proof-only", "deployment-image", "profile-measurement", "enforced-limits", "aggregate-memory", "worker-resource-borrowing", "copies-outside-memory", "workload-overcommit", "principal-overcommit", "poll-work", "control-work", "history", "legacy-history", "worker-history-rows", "fractional-duration"} {
		t.Run(name, func(t *testing.T) {
			q, pool, base, root := queryCapacityFixture(t)
			x := q.ContextQuery
			switch name {
			case "missing":
				q.ContextQuery = nil
			case "worker-proof-only":
				x.Native.Hub = QueryDeploymentPin{}
			case "deployment-image":
				x.Native.Provider.Image = "provider:latest"
			case "profile-measurement":
				x.Native.ProfileDigest = artifact.Digest{8}
			case "enforced-limits":
				x.Native.KeyService.EnforcedLimitsDigest = artifact.Digest{}
			case "copies-outside-memory":
				x.Native.Provider.Limits.WorkerTransientBytes = x.Native.Provider.Limits.MemoryBytes
			case "worker-resource-borrowing":
				x.Native.Worker.Limits.CPUMilli--
				x.Native.Hub.Limits.CPUMilli++
			case "aggregate-memory":
				x.Native.Combined.MemoryBytes--
			case "workload-overcommit":
				x.WorkloadQueries++
			case "principal-overcommit":
				x.PrincipalQueries = x.RootQueries + 1
			case "poll-work":
				x.Profile.Cost.AuditObjects = 2
			case "control-work":
				x.History.ProviderPerControl = 100
			case "legacy-history":
				x.History.Layout = "context-query-history/v1"
			case "worker-history-rows":
				x.Profile.Cost.SQLRows = 12
				body, _ := json.Marshal(x.Profile)
				x.Native.ProfileDigest = sha256.Sum256(body)
			case "history":
				x.Envelope.BackupBytes--
			case "fractional-duration":
				x.Admission += time.Nanosecond
			}
			if _, e := CompileQueryBacking(q, root, base, pool, artifact.Digest{6}, q.ID); e == nil {
				t.Fatal("unqualified query accepted")
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
