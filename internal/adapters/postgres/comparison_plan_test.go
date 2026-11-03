package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const comparisonPlanID = "11111111-1111-4111-8111-111111111111"
const comparisonOtherID = "22222222-2222-4222-8222-222222222222"

// Synthetic protected facts exercise the adapter only, not SQL acceptance or
// a deployment qualification. Actual plan reads still require installed SQL.
func comparisonPlanFixture() (*SharedContextQueryPlans, value.ContextProjectionAuthority, [2]value.ContextQueryPlan) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(4 * time.Second)
	rev := identity.Revision{UID: comparisonPlanID, Generation: 1, Digest: artifact.Digest{1}}
	principal := identity.Principal{Issuer: "https://issuer.example", Subject: "developer", ClientID: "client", Kind: identity.Human}
	location := artifact.Location{ClusterID: comparisonPlanID, ArtifactID: comparisonPlanID, AttemptID: comparisonPlanID}
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: comparisonPlanID, TargetClusterID: comparisonPlanID, StoreID: comparisonPlanID, StorageRegion: "region", AcquisitionClusterID: comparisonPlanID, AcquisitionRegion: "region", ConnectorClusterID: comparisonPlanID, ConnectorRegion: "region", HubClusterID: comparisonPlanID, HubRegion: "region", WorkerConfiguration: rev, HubConfiguration: rev}
	scope := value.ContextProjectionScope{RootID: comparisonPlanID, CaseID: comparisonPlanID, ArtifactID: comparisonPlanID, CaptureID: comparisonPlanID, ClusterID: comparisonPlanID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, SourceFormat: artifact.PprofFormat, DisplayVersion: value.ProfileComparisonDisplayVersion, NativeType: artifact.PprofArtifact, Profile: value.ProfileSummarySelection{SampleType: "cpu", TopN: 20}, Principal: principal, Comparison: value.ProfileComparisonWindow{Normalization: value.ProfileComparisonRaw, Baseline: value.ProfileComparisonBaseline{CaseID: comparisonOtherID, ArtifactID: comparisonOtherID, CaptureID: comparisonOtherID, ClusterID: comparisonPlanID, NamespaceUID: "namespace", WorkloadUID: "other-workload", PodUID: "other-pod", Version: artifact.Digest{4}}}}
	env := value.ContextProjectionEnvironment{RootID: comparisonPlanID, InstallationID: comparisonPlanID, Region: "region", StoreID: comparisonPlanID, Location: location, Principal: principal, PolicyRevision: rev, Path: path, ObservedAt: now, ValidUntil: until, Recovery: artifact.RecoveryProof{InstallationID: comparisonPlanID, IssuerEpoch: comparisonPlanID, Revision: rev, ObservedAt: now, FreshUntil: until}, Processing: artifact.DownloadProcessingProof{RootID: comparisonPlanID, Epoch: comparisonPlanID, CaptureID: comparisonPlanID, Location: location, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}}
	retention := artifact.RetentionProof{RootID: comparisonPlanID, ClusterID: comparisonPlanID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1, ObservedAt: now, ValidUntil: until}
	retention.Sources[0] = artifact.RetentionSourceVersion{ClusterID: comparisonPlanID, ControlNamespaceUID: "control", Epoch: comparisonPlanID, Hub: true, ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}
	a := value.ContextProjectionAuthority{Scope: scope, Environment: env, Retention: retention, PermissionRevision: rev, IdentityRevision: rev, DecisionDigest: artifact.Digest{3}, CheckedAt: now, ValidUntil: until, AccessUntil: now.Add(time.Minute), DeleteBy: now.Add(2 * time.Minute)}
	b := a
	b.Scope, _ = a.Scope.BaselineScope()
	b.Environment.Location.ArtifactID = comparisonOtherID
	b.Environment.Processing.Location = b.Environment.Location
	b.Environment.Processing.CaptureID = comparisonOtherID
	b.Environment.Path.ID = comparisonOtherID
	b.Retention.WorkloadUID, b.Retention.PodUID = b.Scope.WorkloadUID, b.Scope.PodUID
	a.Baseline = &b
	worker := value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: value.ProfileComparisonWorkerBytes, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: value.ProfileComparisonWorkerBytes, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute}
	cost := value.ContextQueryCost{Workers: 1, ReadBatches: value.ContextMaxReadBatches, ReadBytes: value.ContextMaxReadBatches * value.ContextBatchReadWork, StructuredBytes: value.ContextMaxReadBatches * value.ContextResultBytes, WireBytes: value.ContextMaxReadBatches * value.ContextWireBytes, UnwrapAttempts: 3 * value.ContextMaxReadBatches, ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2, AuditObjects: 20, SQLRows: 20, SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}
	var plans [2]value.ContextQueryPlan
	for i, source := range []value.ContextProjectionAuthority{b, a} {
		plans[i] = value.ContextQueryPlan{AcceptanceID: comparisonPlanID, AccountID: comparisonPlanID, AllocationID: comparisonPlanID, RootID: comparisonPlanID, InstallationID: comparisonPlanID, ClusterID: source.Scope.ClusterID, NamespaceUID: source.Scope.NamespaceUID, WorkloadUID: source.Scope.WorkloadUID, AllocationRevision: 1, PoolSource: rev, PolicySource: rev, Principal: principal, Profile: value.ContextQueryResourceProfile{ID: comparisonPlanID, Source: rev, Qualification: rev, Path: source.Environment.Path, Lifetime: value.ContextDefaultQueryTime, Worker: worker, Cost: cost, PollLimit: 4, ControlTransitionLimit: 32}, ObservedAt: now, ValidUntil: until, HardUntil: now.Add(time.Minute), EffectsUntil: now.Add(3 * time.Minute), CleanupUntil: now.Add(4 * time.Minute), RetireBy: now.Add(time.Hour)}
	}
	plans[0].AllocationID = comparisonOtherID
	s := &SharedContextQueryPlans{root: comparisonPlanID, installation: comparisonPlanID, profile: authorization.DownloadWorkerProfile{ClusterID: comparisonPlanID, Configuration: rev, CPUMillis: worker.CPUMilli, MemoryBytes: worker.MemoryBytes, MaxRuntime: worker.Runtime}}
	return s, a, plans
}

type comparisonPlanReader struct {
	plans  [2]value.ContextQueryPlan
	calls  []custodydb.ReadSharedContextQueryPlanParams
	fail   int
	cancel context.CancelFunc
}

func (r *comparisonPlanReader) ReadSharedContextQueryPlan(ctx context.Context, p custodydb.ReadSharedContextQueryPlanParams) ([]byte, error) {
	index := len(r.calls)
	r.calls = append(r.calls, p)
	if r.fail == index+1 {
		return nil, errors.New("unavailable")
	}
	if r.cancel != nil && index == 1 {
		r.cancel()
	}
	return json.Marshal(r.plans[index])
}

func TestComparisonPlanReadsUseOneAccountAndPreserveBothSnapshots(t *testing.T) {
	s, a, plans := comparisonPlanFixture()
	if !a.Valid(time.Now()) {
		t.Fatal("invalid authority fixture")
	}
	reader := &comparisonPlanReader{plans: plans}
	out, err := s.readComparisonPlans(context.Background(), reader, a, comparisonOtherID)
	if err != nil || !reflect.DeepEqual(out, plans) {
		t.Fatal("accepted snapshots changed", err)
	}
	if len(reader.calls) != 2 || reader.calls[0].ProposedAccount != id(comparisonOtherID) || reader.calls[1].ProposedAccount != reader.calls[0].ProposedAccount || reader.calls[0].WorkloadUid != a.Baseline.Scope.WorkloadUID || reader.calls[1].WorkloadUid != a.Scope.WorkloadUID || !reflect.DeepEqual(reader.calls[0].Actor, reader.calls[1].Actor) {
		t.Fatal("pair read lost account/source binding")
	}
	// Existing principal account IDs are returned unchanged rather than replaced
	// with the proposal. Both sources still must agree on the resolved account.
	if out[0].AccountID != comparisonPlanID || out[1].AccountID != comparisonPlanID {
		t.Fatal("proposal rewrote accepted account")
	}
}

func TestComparisonPlanReadRefusesPartialInvalidAndCancelledResults(t *testing.T) {
	for _, mode := range []string{"first-error", "second-error", "account-conflict", "insufficient-worker", "old-worker-configuration", "summary-only-transient", "expired-baseline", "cancelled-after-read", "legacy-authority"} {
		t.Run(mode, func(t *testing.T) {
			s, a, plans := comparisonPlanFixture()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			reader := &comparisonPlanReader{plans: plans}
			switch mode {
			case "first-error":
				reader.fail = 1
			case "second-error":
				reader.fail = 2
			case "account-conflict":
				reader.plans[0].AccountID = comparisonOtherID
			case "insufficient-worker":
				reader.plans[0].Profile.Worker.MemoryBytes--
			case "old-worker-configuration":
				s.profile.MemoryBytes = value.ProfileSummaryWorkerBytes
			case "summary-only-transient":
				reader.plans[0].Profile.Worker.WorkerTransientBytes = value.ProfileSummaryWorkerBytes
				reader.plans[1].Profile.Worker.WorkerTransientBytes = value.ProfileSummaryWorkerBytes
			case "expired-baseline":
				reader.plans[0].ValidUntil = time.Now().Add(-time.Second)
			case "cancelled-after-read":
				reader.cancel = stop
			case "legacy-authority":
				a.Scope, _ = a.Scope.IncidentScope()
				a.Baseline = nil
			}
			out, err := s.readComparisonPlans(ctx, reader, a, comparisonOtherID)
			if err == nil || out != ([2]value.ContextQueryPlan{}) {
				t.Fatal("partial or invalid accepted plans escaped")
			}
		})
	}
	var s *SharedContextQueryPlans
	if out, err := s.ContextComparisonPlans(context.Background(), value.ContextProjectionAuthority{}); err == nil || out != ([2]value.ContextQueryPlan{}) {
		t.Fatal("missing installed reader accepted")
	}
}
