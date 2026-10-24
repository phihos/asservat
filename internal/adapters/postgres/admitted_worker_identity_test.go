package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Query-protocol regression only. It executes the production transaction body
// against explicit rows; real PostgreSQL locking/commit qualification is separate.
type admittedIdentityRows struct {
	trust          custodydb.FleetCurrentTrust
	parent         custodydb.ArtifactDownload
	query          custodydb.ContextQuery
	head           custodydb.DownloadWorkerConfiguration
	revision       custodydb.DownloadWorkerConfigurationRevision
	worker, latest custodydb.DownloadWorker
	now            time.Time
	calls          []string
	hook           func(string)
}

type admittedIdentityRow struct {
	value any
	err   error
}

func (r admittedIdentityRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	v := reflect.ValueOf(r.value)
	if v.NumField() != len(dst) {
		return errors.New("unexpected admitted-identity row width")
	}
	for i := range dst {
		reflect.ValueOf(dst[i]).Elem().Set(v.Field(i))
	}
	return nil
}
func (*admittedIdentityRows) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("identity observation attempted SQL write")
}
func (*admittedIdentityRows) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("identity observation attempted unbounded query")
}
func (r *admittedIdentityRows) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	name := strings.Fields(sql)[2]
	r.calls = append(r.calls, name)
	if r.hook != nil {
		r.hook(name)
	}
	if ctx.Err() != nil {
		return admittedIdentityRow{err: ctx.Err()}
	}
	var row any
	var want []any
	switch name {
	case "ShareFleetTrust":
		row = r.trust
		want = []any{r.trust.InstallationID}
	case "LockDownloadSession":
		row = r.parent
		want = []any{r.parent.ID, r.parent.RootID}
	case "LockContextQuery":
		row = r.query
		want = []any{r.query.ID, r.query.RootID}
	case "ShareWorkerConfiguration":
		row = r.head
		want = []any{r.head.InstallationID, r.head.ClusterID, r.head.SourceUid}
	case "ReadWorkerConfigurationRevision":
		row = r.revision
		want = []any{r.head.InstallationID, r.head.ClusterID, r.head.SourceUid, r.head.Generation}
	case "LockDownloadWorker":
		row = r.worker
		want = []any{r.worker.ID, r.parent.RootID}
	case "LatestDownloadWorker":
		row = r.latest
		want = []any{r.parent.ID, r.parent.RootID}
	case "CurrentTime":
		row = struct{ Time pgtype.Timestamptz }{ts(r.now)}
	default:
		return admittedIdentityRow{err: errors.New("unexpected identity query: " + name)}
	}
	if !reflect.DeepEqual(args, want) {
		return admittedIdentityRow{err: errors.New("changed admitted identity query scope")}
	}
	return admittedIdentityRow{value: row}
}

func admittedIdentityFixture(t *testing.T) (*admittedWorkerIdentity, *admittedIdentityRows, value.DownloadWorker, time.Time) {
	t.Helper()
	w := versionWorkerFixture(t)
	started := w.Intent.CreatedAt.Add(10 * time.Second)
	if w.Intent.Authority.Valid(started) {
		t.Fatal("fixture retained a live human observation")
	}
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	scope := w.Intent.Authority.Scope
	request := artifact.Digest{7}
	parent := custodydb.ArtifactDownload{ID: id(w.Intent.SessionID), RootID: id(scope.RootID), AllocationID: id(w.Intent.SessionID), ArtifactID: id(scope.ArtifactID), PrincipalKey: principalKey(scope.Principal), ActorKey: digest(scope.Principal), RequestDigest: request[:], ScopeJson: encode(scope), State: string(artifact.DownloadPreparing), CreatedAt: ts(w.Intent.CreatedAt), Deadline: ts(w.Intent.RunUntil), OutputLimit: 8192, ReadLimit: 12 << 20, RequestLimit: 3}
	if _, e := decodeDownload(parent); e != nil {
		t.Fatal("invalid admitted parent", e)
	}
	workerReceipt := audit.Receipt{Key: audit.DownloadWorkerAuditKey(w.Intent), Version: "original", ETag: "original", Bytes: 17, SHA256: artifact.Digest{8}}
	worker := custodydb.DownloadWorker{ID: id(w.Intent.ID), SessionID: id(w.Intent.SessionID), RootID: id(scope.RootID), InstallationID: id(w.Binding.InstallationID), Generation: w.Intent.Generation, RunUntil: ts(w.Intent.RunUntil), ClaimedAt: ts(w.Intent.CreatedAt), IntentJson: encode(w.Intent), JobJson: encode(w.Job), BindingJson: encode(w.Binding), AuditReceiptJson: encode(workerReceipt)}
	cfg := value.DownloadWorkerConfiguration{Profile: w.Intent.Profile, RecoveryEpoch: w.Intent.Authority.Environment.RecoveryEpoch, ProtectionDigest: artifact.Digest{9}}
	receipt := audit.Receipt{Key: audit.WorkerConfigurationAuditKey(cfg), Version: "current", ETag: "current", Bytes: 19, SHA256: artifact.Digest{10}}
	if !receipt.ValidWorkerConfiguration(cfg) {
		t.Fatal("invalid current configuration receipt")
	}
	p := w.Intent.Profile
	rev := w.Intent.Authority.Environment.RecoveryRevision
	r := &admittedIdentityRows{
		trust:  custodydb.FleetCurrentTrust{InstallationID: id(p.InstallationID), IssuerEpoch: id(cfg.RecoveryEpoch), SourceUid: rev.UID, SourceGeneration: rev.Generation, SourceDigest: rev.Digest[:], ObservedAt: ts(started.Add(-time.Second)), FreshUntil: ts(started.Add(4 * time.Second))},
		parent: parent, worker: worker, latest: worker, now: started,
		head:     custodydb.DownloadWorkerConfiguration{InstallationID: id(p.InstallationID), ClusterID: id(p.ClusterID), SourceUid: id(p.Configuration.UID), Generation: p.Configuration.Generation, ObservedAt: ts(started), FreshUntil: ts(started.Add(3 * time.Second))},
		revision: custodydb.DownloadWorkerConfigurationRevision{InstallationID: id(p.InstallationID), ClusterID: id(p.ClusterID), SourceUid: id(p.Configuration.UID), Generation: p.Configuration.Generation, SnapshotJson: encode(cfg), AuditReceiptJson: encode(receipt)},
	}
	return &admittedWorkerIdentity{root: scope.RootID, profile: p}, r, w, started
}

func TestAdmittedWorkerIdentityUsesAdmissionWithoutRenewingHumanAuthority(t *testing.T) {
	s, rows, w, started := admittedIdentityFixture(t)
	before := slices.Clone(rows.worker.IntentJson)
	var effects int
	err := s.current(context.Background(), custodydb.New(rows), w.Intent.Acquisition().Parent, w.Intent.ID, started, func(_ context.Context, _ *custodydb.Queries, checked admittedWorkerCheck, now time.Time) error {
		effects++
		if checked.download != w || checked.worker != w.Acquisition() || checked.recoveryEpoch != w.Intent.Authority.Environment.RecoveryEpoch || !checked.observedAt.Equal(started) || !checked.freshUntil.Equal(rows.head.FreshUntil.Time) || !now.Equal(started) {
			t.Fatal("admitted identity or original bound changed")
		}
		return nil
	})
	want := []string{"ShareFleetTrust", "LockDownloadSession", "ShareWorkerConfiguration", "ReadWorkerConfigurationRevision", "CurrentTime", "LockDownloadWorker", "LatestDownloadWorker", "CurrentTime", "CurrentTime"}
	if err != nil || effects != 1 || !slices.Equal(rows.calls, want) {
		t.Fatalf("identity enrollment: err=%v effects=%d calls=%v", err, effects, rows.calls)
	}
	if !slices.Equal(before, rows.worker.IntentJson) || w.Intent.Authority.Valid(started) {
		t.Fatal("enrollment renewed stored human authority")
	}
}

func TestAdmittedWorkerIdentityRefusesCurrentFencesAfterBlockingWork(t *testing.T) {
	for _, mode := range []string{"stopped-parent", "expired-parent", "recovery-blocked", "recovery-expired-after-worker-lock", "configuration-suspended", "configuration-replaced", "configuration-expired-after-worker-lock", "wrong-issuer-epoch", "terminated-worker", "retired-worker", "replacement-worker", "missing-worker-audit", "caller-cancelled-after-worker-lock", "original-operation-expired-after-worker-lock", "cutoff-after-effect"} {
		t.Run(mode, func(t *testing.T) {
			s, rows, w, started := admittedIdentityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "stopped-parent":
				rows.parent.State = string(artifact.DownloadCancelled)
			case "expired-parent":
				rows.parent.Deadline = ts(started)
			case "recovery-blocked":
				rows.trust.RecoveryBlocked = true
			case "recovery-expired-after-worker-lock":
				rows.head.FreshUntil = ts(started.Add(5 * time.Second))
			case "wrong-issuer-epoch":
				rows.trust.IssuerEpoch = id("10000000-0000-4000-8000-000000000002")
			case "configuration-suspended", "configuration-replaced":
				var c value.DownloadWorkerConfiguration
				if json.Unmarshal(rows.revision.SnapshotJson, &c) != nil {
					t.Fatal("configuration fixture")
				}
				if mode == "configuration-suspended" {
					c.Suspended = true
				} else {
					c.Profile.Configuration.Generation++
				}
				rows.revision.SnapshotJson, _ = json.Marshal(c)
			case "terminated-worker":
				rows.worker.TerminationJson = []byte(`{}`)
			case "retired-worker":
				rows.worker.RetiredProofJson = []byte(`{}`)
			case "replacement-worker":
				rows.latest.ID = id("10000000-0000-4000-8000-000000000002")
			case "missing-worker-audit":
				rows.worker.AuditReceiptJson = nil
			}
			rows.hook = func(name string) {
				if name != "LockDownloadWorker" {
					return
				}
				switch mode {
				case "recovery-expired-after-worker-lock":
					rows.now = rows.trust.FreshUntil.Time
				case "configuration-expired-after-worker-lock":
					rows.now = rows.head.FreshUntil.Time
				case "original-operation-expired-after-worker-lock":
					rows.now = started.Add(5 * time.Second)
				case "caller-cancelled-after-worker-lock":
					cancel()
				}
			}
			var effects int
			err := s.current(ctx, custodydb.New(rows), w.Intent.Acquisition().Parent, w.Intent.ID, started, func(context.Context, *custodydb.Queries, admittedWorkerCheck, time.Time) error {
				effects++
				if mode == "cutoff-after-effect" {
					rows.now = rows.head.FreshUntil.Time
				}
				return nil
			})
			wantEffects := 0
			if mode == "cutoff-after-effect" {
				wantEffects = 1
			}
			if err == nil || effects != wantEffects {
				t.Fatalf("lost identity fence: err=%v effects=%d calls=%v", err, effects, rows.calls)
			}
		})
	}
}

// A structurally accepted query and worker are synthetic rows here. The guard
// must use their persisted admission, not a new public query call or authority.
func admittedProjectionIdentityFixture(t *testing.T) (*admittedWorkerIdentity, *admittedIdentityRows, value.AcquisitionWorker, time.Time) {
	t.Helper()
	s, rows, original, started := admittedIdentityFixture(t)
	created := started.Add(-6 * time.Second)
	p, a := original.Intent.Profile, original.Intent.Authority
	scope := query.ContextProjectionScope{RootID: a.Scope.RootID, CaseID: original.Intent.ID, ArtifactID: a.Scope.ArtifactID,
		CaptureID: a.Scope.CaptureID, ClusterID: a.Scope.ClusterID, NamespaceUID: a.Scope.NamespaceUID,
		WorkloadUID: a.Scope.WorkloadUID, PodUID: a.Scope.PodUID, Version: a.Scope.Version,
		SourceProjectionDigest: query.ContextSourceProjectionDigest(), SourceFormat: artifact.ContextFormat,
		DisplayVersion: query.ContextDisplayVersion, Selection: query.LineSelection{LineStart: 1, MaxLines: 200}, Principal: a.Scope.Principal}
	path := query.ContextProjectionPath{Purpose: query.ContextProjectionPurpose, ID: original.Intent.ID, TargetClusterID: scope.ClusterID,
		StoreID: a.Environment.StoreID, StorageRegion: "synthetic", AcquisitionClusterID: p.ClusterID, AcquisitionRegion: "synthetic",
		ConnectorClusterID: p.ClusterID, ConnectorRegion: "synthetic", HubClusterID: p.ClusterID, HubRegion: "synthetic",
		WorkerConfiguration: p.Configuration, HubConfiguration: p.Configuration}
	limits := query.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20,
		WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10, ProviderConcurrency: 1, AuthenticationConcurrency: 1,
		Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute}
	cost := query.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * query.ContextBatchReadWork,
		StructuredBytes: 2 * query.ContextResultBytes, WireBytes: 2 * query.ContextWireBytes, UnwrapAttempts: 6,
		ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2, AuditObjects: 20, SQLRows: 20,
		SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}
	plan := query.ContextQueryPlan{AcceptanceID: original.Intent.ID, AccountID: original.Intent.ID, AllocationID: original.Intent.ID,
		RootID: scope.RootID, InstallationID: p.InstallationID, ClusterID: scope.ClusterID, NamespaceUID: scope.NamespaceUID,
		WorkloadUID: scope.WorkloadUID, AllocationRevision: 1, PoolSource: p.Configuration, PolicySource: p.Configuration, Principal: scope.Principal,
		Profile: query.ContextQueryResourceProfile{ID: original.Intent.ID, Source: p.Configuration, Qualification: p.Configuration,
			Path: path, Lifetime: query.ContextDefaultQueryTime, Worker: limits, Cost: cost, PollLimit: 4, ControlTransitionLimit: 32},
		ObservedAt: created, ValidUntil: created.Add(5 * time.Second), HardUntil: created.Add(time.Minute), EffectsUntil: created.Add(3 * time.Minute),
		CleanupUntil: created.Add(4 * time.Minute), RetireBy: created.Add(time.Hour)}
	q := query.ContextQuery{ID: original.Intent.SessionID, OperationID: original.Intent.ID, WorkerID: original.Intent.ID,
		Scope: scope, Plan: plan, RecoveryIssuerEpoch: a.Environment.RecoveryEpoch, RecoveryRevision: a.Environment.RecoveryRevision,
		CreatedAt: created, Deadline: created.Add(query.ContextDefaultQueryTime), WorkerUntil: created.Add(time.Minute),
		CredentialUntil: created.Add(2 * time.Minute), ProviderUntil: created.Add(time.Minute), CleanupUntil: created.Add(3 * time.Minute)}
	w := original.Acquisition()
	w.Intent.Parent = value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}
	w.Intent.CreatedAt, w.Intent.RunUntil = q.CreatedAt, q.WorkerUntil
	w.Binding.Parent, w.Binding.Job = w.Intent.Parent, w.Intent.JobName()
	i := query.ContextProjectionWorkerIntent{Query: q, Worker: w.Intent}
	if !q.Valid() || !i.Valid() || !w.Valid() || q.Plan.Valid(q.Scope, started) {
		t.Fatal("invalid admitted projection fixture or unexpectedly current admission observation")
	}
	encode := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rows.query = custodydb.ContextQuery{ID: id(q.ID), RootID: id(q.Scope.RootID), AllocationID: id(q.Plan.AllocationID),
		AccountID: id(q.Plan.AccountID), PrincipalKey: principalKey(q.Scope.Principal), Actor: encode(q.Scope.Principal), Query: encode(q),
		OperationID: id(q.OperationID), WorkerID: id(q.WorkerID), CreatedAt: ts(q.CreatedAt), Deadline: ts(q.Deadline),
		CleanupUntil: ts(q.CleanupUntil), RetireBy: ts(q.Plan.RetireBy), IssuerEpoch: id(q.RecoveryIssuerEpoch)}
	receipt := audit.Receipt{Key: audit.ProjectionWorkerKey(i), Version: "original", ETag: "original", Bytes: 17, SHA256: artifact.Digest{8}}
	rows.worker.SessionID, rows.worker.AllocationID = pgtype.UUID{}, pgtype.UUID{}
	rows.worker.QueryID, rows.worker.QueryAllocationID = id(q.ID), id(q.Plan.AllocationID)
	rows.worker.PrincipalKey, rows.worker.RunUntil, rows.worker.ClaimedAt = principalKey(q.Scope.Principal), ts(w.Intent.RunUntil), ts(created)
	rows.worker.IntentJson, rows.worker.JobJson, rows.worker.BindingJson, rows.worker.AuditReceiptJson = encode(i), encode(w.Job), encode(w.Binding), encode(receipt)
	return s, rows, w, started
}

func TestAdmittedWorkerIdentityUsesExactQueryParentWithoutPublicCall(t *testing.T) {
	for _, mode := range []string{"valid", "uncertain", "wrong-worker", "wrong-epoch", "expired-query", "mixed-parent", "missing-audit", "unclaimed", "terminated", "retired", "expired-after-worker-lock"} {
		t.Run(mode, func(t *testing.T) {
			s, rows, w, started := admittedProjectionIdentityFixture(t)
			var q query.ContextQuery
			if err := json.Unmarshal(rows.query.Query, &q); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "uncertain":
				rows.query.Uncertain = true
			case "wrong-worker":
				q.WorkerID = "10000000-0000-4000-8000-000000000002"
				rows.query.WorkerID = id(q.WorkerID)
			case "wrong-epoch":
				q.RecoveryIssuerEpoch = "10000000-0000-4000-8000-000000000002"
				rows.query.IssuerEpoch = id(q.RecoveryIssuerEpoch)
			case "expired-query":
				q.Deadline, rows.query.Deadline = started, ts(started)
			case "mixed-parent":
				rows.worker.SessionID = id(q.ID)
			case "missing-audit":
				rows.worker.AuditReceiptJson = nil
			case "unclaimed":
				rows.worker.ClaimedAt = pgtype.Timestamptz{}
			case "terminated":
				rows.worker.TerminationJson = []byte(`{}`)
			case "retired":
				rows.worker.RetiredProofJson = []byte(`{}`)
			case "expired-after-worker-lock":
				rows.head.FreshUntil, rows.trust.FreshUntil = ts(started.Add(5*time.Second)), ts(started.Add(5*time.Second))
				rows.hook = func(name string) {
					if name == "LockDownloadWorker" {
						rows.now = q.Deadline
					}
				}
			}
			rows.query.Query, _ = json.Marshal(q)
			if mode == "expired-query" {
				// Keep the immutable parent in the worker identical so this
				// refuses the elapsed cutoff, not a different stored query.
				rows.worker.IntentJson, _ = json.Marshal(query.ContextProjectionWorkerIntent{Query: q, Worker: w.Intent})
			}
			before := slices.Clone(rows.worker.IntentJson)
			effects := 0
			err := s.current(context.Background(), custodydb.New(rows), w.Intent.Parent, w.Intent.ID, started, func(_ context.Context, _ *custodydb.Queries, c admittedWorkerCheck, _ time.Time) error {
				effects++
				if c.worker != w || c.download != (value.DownloadWorker{}) || c.recoveryEpoch != q.RecoveryIssuerEpoch {
					t.Fatal("query identity converted into download authority")
				}
				return nil
			})
			if mode == "valid" {
				want := []string{"ShareFleetTrust", "LockContextQuery", "ShareWorkerConfiguration", "ReadWorkerConfigurationRevision", "CurrentTime", "LockDownloadWorker", "CurrentTime", "CurrentTime"}
				if err != nil || effects != 1 || !slices.Equal(rows.calls, want) {
					t.Fatal("query identity failed or requested public authority", err, effects, rows.calls)
				}
			} else if err == nil || effects != 0 {
				t.Fatal("invalid query admission authorized identity effect", err, effects)
			}
			if !slices.Equal(before, rows.worker.IntentJson) {
				t.Fatal("identity guard rewrote original query admission")
			}
		})
	}
}
