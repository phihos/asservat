package analysis

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

func comparisonKeyFixture(t *testing.T) (ContextQuery, ContextReadBatch, ContextProjectionAuthority) {
	t.Helper()
	a, b, i := comparisonPlansFixture()
	q, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, b, i, a.CheckedAt)
	if err != nil {
		t.Fatal(err)
	}
	w := ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: queryTestID, PodUID: queryTestID, ProcessEpoch: queryTestID, Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	request := ContextQueryRequest{Call: ContextQueryCall{ID: queryTestID, RootID: a.Scope.RootID, Tool: "compare_profiles", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: a.Scope.Principal, StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}, OwnerID: queryTestID, HubProcessEpoch: queryTestID}
	batch := ContextReadBatch{QueryID: q.ID, ID: queryTestID, OperationID: queryTestID, Generation: 1, Worker: w, Request: request, StartedAt: a.CheckedAt, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}
	if !batch.Current(q, a, a.CheckedAt) {
		t.Fatal("invalid compound batch")
	}
	return q, batch, a
}
func TestProfileComparisonKeyChildrenAreDeterministicDistinctAndOrdinalBound(t *testing.T) {
	q, b, a := comparisonKeyFixture(t)
	ids, e := ProfileComparisonKeyChildIDs(b.ID)
	again, _ := ProfileComparisonKeyChildIDs(b.ID)
	if e != nil || ids != again || ids[0] == ids[1] || ids[0] == b.ID || ids[1] == b.ID {
		t.Fatal("unstable or shared source key identity", ids, e)
	}
	other, _ := ProfileComparisonKeyChildIDs(queryOtherID)
	if other[0] == ids[0] || other[1] == ids[1] {
		t.Fatal("another batch reused children")
	}
	for _, bad := range []string{"", "not-a-uuid", "00000000-0000-0000-0000-000000000000"} {
		if _, e := ProfileComparisonKeyChildIDs(bad); e == nil {
			t.Fatal("invalid batch child identity")
		}
	}
	for ordinal := range ids {
		version := q.Scope.Version
		if ordinal == 0 {
			version = q.Scope.Comparison.Baseline.Version
		}
		child := ContextProjectionComparisonKeyChild{ID: ids[ordinal], QueryID: q.ID, BatchID: b.ID, WorkerID: q.WorkerID, ProcessEpoch: b.Worker.ProcessEpoch, SourceOrdinal: ordinal, SourceVersion: version, AuthorityDigest: a.DecisionDigest, PublicKey: artifact.Digest{3}, Certificate: b.Worker.Certificate, Scope: authorization.KeyScope{InstallationID: q.Plan.InstallationID, Purpose: "artifact", KeyID: "evidence"}, CreatedAt: b.StartedAt, Until: b.Until}
		if !child.Valid(q, b, a, b.StartedAt) {
			t.Fatal("valid compact child refused", ordinal)
		}
		for name, mutate := range map[string]func(*ContextProjectionComparisonKeyChild){
			"batch-identity":   func(c *ContextProjectionComparisonKeyChild) { c.ID = b.ID },
			"other-ordinal-id": func(c *ContextProjectionComparisonKeyChild) { c.ID = ids[1-ordinal] },
			"ordinal":          func(c *ContextProjectionComparisonKeyChild) { c.SourceOrdinal = 2 },
			"version":          func(c *ContextProjectionComparisonKeyChild) { c.SourceVersion[0]++ },
			"parent-decision":  func(c *ContextProjectionComparisonKeyChild) { c.AuthorityDigest[0]++ },
			"worker":           func(c *ContextProjectionComparisonKeyChild) { c.WorkerID = queryOtherID },
			"process":          func(c *ContextProjectionComparisonKeyChild) { c.ProcessEpoch = queryOtherID },
			"certificate":      func(c *ContextProjectionComparisonKeyChild) { c.Certificate[0]++ },
			"key":              func(c *ContextProjectionComparisonKeyChild) { c.PublicKey = artifact.Digest{} },
			"query":            func(c *ContextProjectionComparisonKeyChild) { c.QueryID = queryOtherID },
			"batch":            func(c *ContextProjectionComparisonKeyChild) { c.BatchID = queryOtherID },
			"time":             func(c *ContextProjectionComparisonKeyChild) { c.Until = c.Until.Add(time.Second) },
			"scope":            func(c *ContextProjectionComparisonKeyChild) { c.Scope.Purpose = "audit" },
		} {
			t.Run(name, func(t *testing.T) {
				bad := child
				mutate(&bad)
				if bad.Valid(q, b, a, b.StartedAt) {
					t.Fatal("changed compact source identity accepted")
				}
			})
		}
		raw, err := json.Marshal(child)
		var back ContextProjectionComparisonKeyChild
		if err != nil || json.Unmarshal(raw, &back) != nil || back != child {
			t.Fatal("compact child roundtrip failed", err)
		}
	}
	// Repeating the identical artifact still gives each source label its own row
	// and role mask. The child identity derives from batch+ordinal, not artifact AAD.
	a.Scope.Comparison.Baseline = ProfileComparisonBaseline{CaseID: a.Scope.CaseID, ArtifactID: a.Scope.ArtifactID, CaptureID: a.Scope.CaptureID, ClusterID: a.Scope.ClusterID, NamespaceUID: a.Scope.NamespaceUID, WorkloadUID: a.Scope.WorkloadUID, PodUID: a.Scope.PodUID, Version: a.Scope.Version}
	sameIDs, _ := ProfileComparisonKeyChildIDs(b.ID)
	if sameIDs != ids {
		t.Fatal("artifact identity changed ordinal child IDs")
	}
}

func TestProfileComparisonActualControlEncodingBounds(t *testing.T) {
	a := maximumComparisonAuthority()
	start := a.CheckedAt
	plan := func(source ContextProjectionAuthority) ContextQueryPlan {
		p := queryPlan(source)
		p.AllocationRevision = 1 << 60
		p.Profile.Lifetime = ContextMaxQueryTime
		p.Profile.PollLimit, p.Profile.ControlTransitionLimit = 1000000, 1000000
		w := &p.Profile.Worker
		w.CPUMilli = 4000
		w.MemoryBytes, w.WorkerTransientBytes = 8<<30, 8<<30
		w.HubTransientBytes = 1 << 60
		w.ProviderConcurrency, w.AuthenticationConcurrency = 1<<60, 1<<60
		w.Runtime = 8 * time.Hour
		w.CredentialLifetime, w.ProviderEffectLifetime, w.Cleanup = 1<<63-1, 1<<63-1, 1<<63-1
		c := &p.Profile.Cost
		c.ProviderRequests, c.AuthenticationRequests, c.SigningAttempts, c.AuditObjects, c.SQLRows, c.SQLBytes, c.WALBytes, c.BackupBytes = 1<<60, 1<<60, 1<<60, 1<<60, 1<<60, 1<<60, 1<<60, 1<<60
		p.HardUntil = start.Add(time.Minute)
		p.EffectsUntil = start.Add(w.CredentialLifetime)
		p.CleanupUntil = p.EffectsUntil.Add(w.Cleanup)
		p.RetireBy = p.CleanupUntil.Add(time.Minute)
		return p
	}
	bp, ip := plan(*a.Baseline), plan(a)
	bp.AllocationID = queryOtherID
	q, err := NewProfileComparisonQuery(queryTestID, queryTestID, queryTestID, a, bp, ip, start)
	if err != nil {
		t.Fatal("maximum complete pair query invalid", err)
	}
	digest := a.DecisionDigest
	w := ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: queryTestID, PodUID: queryTestID, ProcessEpoch: queryTestID, Certificate: digest, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	request := ContextQueryRequest{Call: ContextQueryCall{ID: queryTestID, RootID: q.Scope.RootID, Tool: "compare_profiles", InputFormat: "context-query-input/v1", MACVersion: strings.Repeat("<", 64), InputDigest: digest, PrincipalDigest: digest, Principal: a.Scope.Principal, StartedAt: start, Until: a.ValidUntil, WriteUntil: start.Add(30 * time.Second)}, OwnerID: queryTestID, HubProcessEpoch: queryTestID}
	b := ContextReadBatch{QueryID: q.ID, ID: queryTestID, OperationID: queryTestID, Generation: 1, Worker: w, Request: request, StartedAt: start, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}
	if !b.Current(q, a, start) {
		t.Fatal("maximum complete batch invalid")
	}
	ids, _ := ProfileComparisonKeyChildIDs(b.ID)
	child := ContextProjectionComparisonKeyChild{ID: ids[0], QueryID: q.ID, BatchID: b.ID, WorkerID: q.WorkerID, ProcessEpoch: w.ProcessEpoch, SourceOrdinal: 0, SourceVersion: q.Scope.Comparison.Baseline.Version, AuthorityDigest: a.DecisionDigest, PublicKey: digest, Certificate: w.Certificate, Scope: authorization.KeyScope{InstallationID: q.Plan.InstallationID, Purpose: "artifact", KeyID: strings.Repeat("x", 128)}, CreatedAt: start, Until: a.ValidUntil}
	if !child.Valid(q, b, a, start) {
		t.Fatal("maximum compact child invalid")
	}
	operation := authorization.NativeOperation{Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing, Reference: authorization.NativeReference{InstallationID: q.Plan.InstallationID, WorkerID: q.WorkerID, OperationID: b.ID, QueryID: q.ID, Fence: b.Generation}, Kind: authorization.NativeProjection, HubPodUID: queryTestID, HubProcessEpoch: queryTestID, WorkerPodUID: w.PodUID, WorkerPublicKey: digest, SourceVersion: q.Scope.Version, ParentID: b.ID, Generation: b.Generation, StartedAt: start, Until: a.ValidUntil}
	operation.Baseline = authorization.NativeProjectionSource{Path: a.Baseline.Environment.Path.AcquisitionPath(), Processing: a.Baseline.Environment.Processing, SourceVersion: a.Scope.Comparison.Baseline.Version}
	if !operation.Valid() || !operation.CurrentValid(start) {
		t.Fatal("maximum native operation invalid")
	}
	text := func(n int) string { return strings.Repeat("<", n) }
	profile := authorization.DownloadWorkerProfile{Configuration: q.Plan.Profile.Path.WorkerConfiguration, InstallationID: q.Plan.InstallationID, ClusterID: q.Plan.Profile.Path.AcquisitionClusterID, Namespace: text(63), NamespaceUID: text(64), ServiceAccount: text(253), ServiceAccountUID: text(64), Image: text(384) + "@sha256:" + strings.Repeat("f", 64), ControlConfig: text(253), ControlConfigUID: text(64), PriorityClass: text(253), PriorityClassUID: text(64), ImagePullSecrets: [4]string{text(253), strings.Repeat(">", 253), strings.Repeat("&", 253), text(252) + ">"}, ControlDigest: digest, CPUMillis: 4000, MemoryBytes: 8 << 30, MaxRuntime: 8 * time.Hour, StoreCredentialSecret: text(253), StoreCredentialSecretUID: queryTestID}
	intent := ContextProjectionWorkerIntent{Query: q, Worker: authorization.AcquisitionWorkerIntent{ID: q.WorkerID, Parent: authorization.AcquisitionParent{Purpose: authorization.AcquisitionProjection, ID: q.ID}, Profile: profile, CreatedAt: q.CreatedAt, RunUntil: q.WorkerUntil}}
	if !intent.Valid() {
		t.Fatal("maximum complete worker intent invalid")
	}
	for name, v := range map[string]struct {
		value any
		limit int
	}{"query": {q, 96 << 10}, "authority": {a, 128 << 10}, "batch": {b, 32 << 10}, "native-operation": {operation, 16 << 10}, "worker-intent": {intent, 96 << 10}, "compact-key-child": {child, 4096}} {
		raw, e := json.Marshal(v.value)
		if e != nil || len(raw) > v.limit {
			t.Fatal("bounded control encoding exceeds proposed purpose limit", name, len(raw), v.limit, e)
		}
		t.Logf("maximum valid complete %s=%dB; proposed comparison-purpose limit=%dB", name, len(raw), v.limit)
	}
}
