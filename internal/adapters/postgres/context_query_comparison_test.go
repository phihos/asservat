package postgres

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	authorization "asservat.local/asservat/internal/domain/authorization"
)

func comparisonLedgerFixture(t *testing.T) (value.ContextQuery, value.ContextProjectionAuthority, value.ContextReadBatch, authorization.NativeOperation) {
	t.Helper()
	_, a, plans := comparisonPlanFixture()
	q, e := value.NewProfileComparisonQuery(comparisonPlanID, comparisonPlanID, comparisonPlanID, a, plans[0], plans[1], a.CheckedAt)
	if e != nil {
		t.Fatal(e)
	}
	w := value.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: comparisonPlanID, PodUID: comparisonPlanID, ProcessEpoch: comparisonPlanID, Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	r := value.ContextQueryRequest{Call: value.ContextQueryCall{ID: q.OperationID, RootID: q.Scope.RootID, Tool: "compare_profiles", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: artifact.Digest{2}, PrincipalDigest: artifact.Digest{3}, Principal: q.Scope.Principal, StartedAt: a.CheckedAt, Until: a.ValidUntil, WriteUntil: a.CheckedAt.Add(30 * time.Second)}, OwnerID: comparisonPlanID, HubProcessEpoch: comparisonPlanID}
	b := value.ContextReadBatch{QueryID: q.ID, ID: comparisonPlanID, OperationID: q.OperationID, Generation: 1, Worker: w, Request: r, StartedAt: a.CheckedAt, Until: a.ValidUntil, CleanupUntil: q.CleanupUntil}
	o := authorization.NativeOperation{Path: a.Environment.Path.AcquisitionPath(), Processing: a.Environment.Processing, Reference: authorization.NativeReference{InstallationID: q.Plan.InstallationID, QueryID: q.ID, WorkerID: q.WorkerID, OperationID: b.ID, Fence: b.Generation}, Kind: authorization.NativeProjection, HubPodUID: comparisonPlanID, HubProcessEpoch: r.HubProcessEpoch, WorkerPodUID: w.PodUID, WorkerPublicKey: artifact.Digest{4}, SourceVersion: q.Scope.Version, ParentID: b.ID, Generation: b.Generation, StartedAt: a.CheckedAt, Until: a.ValidUntil, Baseline: authorization.NativeProjectionSource{Path: a.Baseline.Environment.Path.AcquisitionPath(), Processing: a.Baseline.Environment.Processing, SourceVersion: q.Scope.Comparison.Baseline.Version}}
	if !b.Current(q, a, a.CheckedAt) || !o.CurrentValid(a.CheckedAt) {
		t.Fatal("invalid compound ledger fixture")
	}
	return q, a, b, o
}
func comparisonJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestComparisonLedgerViewsPreserveEachCompleteSourceAndParent(t *testing.T) {
	q, a, _, _ := comparisonLedgerFixture(t)
	for _, baseline := range []bool{false, true} {
		child, authority := projectionQuerySource(q, a, baseline)
		if !child.Current(authority, a.CheckedAt) || child.BaselinePlan != (value.ContextQueryPlan{}) || authority.Baseline != nil || child.Scope.Comparison != (value.ProfileComparisonWindow{}) {
			t.Fatal("source view lost existing fences", baseline)
		}
		if baseline && (child.Plan != q.BaselinePlan || child.Scope.Version != q.Scope.Comparison.Baseline.Version) || !baseline && (child.Plan != q.Plan || child.Scope.Version != q.Scope.Version) {
			t.Fatal("source labels swapped")
		}
	}
	if !q.Current(a, a.CheckedAt) || a.Baseline == nil {
		t.Fatal("source view modified compound parent")
	}
	if !projectionAdmissionPlansCurrent(q, a.CheckedAt) || projectionAdmissionPlansCurrent(q, q.BaselinePlan.ValidUntil) {
		t.Fatal("admission renewed a plan observation")
	}
}
func TestComparisonLedgerRowBindsSecondaryAllocationAndPurposeBounds(t *testing.T) {
	q, a, _, _ := comparisonLedgerFixture(t)
	row := custodydb.ContextQuery{ID: id(q.ID), RootID: id(q.Scope.RootID), AllocationID: id(q.Plan.AllocationID), BaselineAllocationID: id(q.BaselinePlan.AllocationID), AccountID: id(q.Plan.AccountID), PrincipalKey: principalKey(q.Scope.Principal), Actor: comparisonJSON(t, q.Scope.Principal), Query: comparisonJSON(t, q), OperationID: id(q.OperationID), WorkerID: id(q.WorkerID), CreatedAt: ts(q.CreatedAt), Deadline: ts(q.Deadline), CleanupUntil: ts(q.CleanupUntil), RetireBy: ts(q.Plan.RetireBy), IssuerEpoch: id(q.RecoveryIssuerEpoch)}
	if got, e := queryFromRow(row); e != nil || !got.Equal(q) {
		t.Fatal("compound row decode", e)
	}
	altered := row
	altered.BaselineAllocationID = id("")
	if _, e := queryFromRow(altered); e == nil {
		t.Fatal("secondary allocation column was ignored")
	}
	altered = row
	altered.Query = append(append([]byte{}, row.Query...), bytes.Repeat([]byte{' '}, (64<<10)-len(row.Query)+1)...)
	if _, e := queryFromRow(altered); e != nil {
		t.Fatal("pair-specific96KiB decoder not used", e)
	}
	legacy, authority := projectionQuerySource(q, a, false)
	altered = row
	altered.Query = append(comparisonJSON(t, legacy), bytes.Repeat([]byte{' '}, 64<<10)...)
	altered.BaselineAllocationID = id("")
	if _, e := queryFromRow(altered); e == nil {
		t.Fatal("legacy row limit broadened")
	}
	if projectionQueryBytes(legacy) != 64<<10 || projectionAuthorityBytes(authority) != 64<<10 || projectionQueryBytes(q) != 96<<10 || projectionAuthorityBytes(a) != 128<<10 {
		t.Fatal("purpose bounds changed")
	}
}
func TestComparisonNativeRecordRequiresBothOriginalSourcePins(t *testing.T) {
	q, a, b, o := comparisonLedgerFixture(t)
	row := custodydb.ContextQueryBatch{ID: id(b.ID), QueryID: id(q.ID), OperationID: id(b.OperationID), Generation: int16(b.Generation), Batch: comparisonJSON(t, b), ClaimID: id(b.ID), NativeOperation: comparisonJSON(t, o), NativeAuthority: comparisonJSON(t, a)}
	if _, got, _, e := projectionNativeRecord(row, q); e != nil || !got.Equal(o) {
		t.Fatal("paired private record refused", e)
	}
	for name, mutate := range map[string]func(*authorization.NativeOperation){
		"missing":             func(o *authorization.NativeOperation) { o.Baseline = authorization.NativeProjectionSource{} },
		"baseline-version":    func(o *authorization.NativeOperation) { o.Baseline.SourceVersion[0]++ },
		"baseline-path":       func(o *authorization.NativeOperation) { o.Baseline.Path.ID = comparisonPlanID },
		"baseline-processing": func(o *authorization.NativeOperation) { o.Baseline.Processing.StateDigest[0]++ },
		"incident-version":    func(o *authorization.NativeOperation) { o.SourceVersion[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := o
			mutate(&changed)
			bad := row
			bad.NativeOperation = comparisonJSON(t, changed)
			if _, _, _, e := projectionNativeRecord(bad, q); e == nil {
				t.Fatal("private operation lost exact source binding")
			}
		})
	}
	legacy, authority := projectionQuerySource(q, a, false)
	if projectionNativeBaselineMatches(o, authority) {
		t.Fatal("legacy scope accepted baseline operation")
	}
	o.Baseline = authorization.NativeProjectionSource{}
	if !projectionNativeBaselineMatches(o, authority) || legacy.Scope.Comparison != (value.ProfileComparisonWindow{}) {
		t.Fatal("legacy zero-baseline behavior changed")
	}
}

func TestComparisonFullWorkerIntentCleanupUsesPurposeBound(t *testing.T) {
	q, a, _, _ := comparisonLedgerFixture(t)
	profile := authorization.DownloadWorkerProfile{Configuration: q.Plan.Profile.Path.WorkerConfiguration, InstallationID: q.Plan.InstallationID, ClusterID: q.Plan.Profile.Path.AcquisitionClusterID, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "acquisition", ServiceAccountUID: "account", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "config", PriorityClass: "workers", PriorityClassUID: "priority", ControlDigest: artifact.Digest{1}, CPUMillis: q.Plan.Profile.Worker.CPUMilli, MemoryBytes: q.Plan.Profile.Worker.MemoryBytes, MaxRuntime: 8 * time.Hour}
	for _, legacy := range []bool{false, true} {
		selected := q
		if legacy {
			selected, _ = projectionQuerySource(q, a, false)
		}
		intent := value.ContextProjectionWorkerIntent{Query: selected, Worker: authorization.AcquisitionWorkerIntent{ID: selected.WorkerID, Parent: authorization.AcquisitionParent{Purpose: authorization.AcquisitionProjection, ID: selected.ID}, Profile: profile, CreatedAt: selected.CreatedAt, RunUntil: selected.WorkerUntil}}
		if !intent.Valid() {
			t.Fatal("worker intent fixture invalid")
		}
		encoded := comparisonJSON(t, intent)
		encoded = append(encoded, bytes.Repeat([]byte{' '}, (64<<10)+1-len(encoded))...)
		row := custodydb.DownloadWorker{ID: id(selected.WorkerID), QueryID: id(selected.ID), RootID: id(selected.Scope.RootID), InstallationID: id(selected.Plan.InstallationID), QueryAllocationID: id(selected.Plan.AllocationID), BaselineQueryAllocationID: id(selected.BaselinePlan.AllocationID), PrincipalKey: principalKey(selected.Scope.Principal), Generation: 1, IntentJson: encoded, RunUntil: ts(selected.WorkerUntil)}
		workers := &ProjectionWorkers{queries: &ContextQueries{root: selected.Scope.RootID}, profile: profile}
		got, err := workers.cleanupState(row)
		if legacy && err == nil {
			t.Fatal("legacy full intent decoder broadened")
		}
		if !legacy && (err != nil || !got.Intent.Query.Equal(q)) {
			t.Fatal("accepted pair full intent lost at historical cleanup decoder", err)
		}
	}
}
