package presentation

import (
	"context"
	"fmt"
	"testing"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// Synthetic ports around the real C18 coordinator. These fixtures establish
// C20 ordering/ownership only, never SQL acknowledgement or native authority.
const bridgeID = "11111111-1111-4111-8111-111111111111"

// All authorities/backing below are explicit component fakes. They exercise
// composition ordering and uncertainty, not production SQL/C-07/C-08/C-14 proof.
type bridgeFixture struct {
	now                                                                          time.Time
	serial                                                                       int
	a                                                                            value.ContextProjectionAuthority
	i                                                                            identity.Identity
	p                                                                            value.ContextQueryPlan
	q                                                                            value.ContextQuery
	s                                                                            analysisapp.ContextProjectionService
	admissions, starts, polls, observations, batches, claims, reads, completions int
	active                                                                       bool
	queryFresh, batchFresh, claimFresh, ready                                    bool
	queryErr, claimErr, closeErr, permitErr, errorAfterRead                      error
	authorityHook                                                                func()
	observeHook                                                                  func()
	routeHook, planHook, claimHook                                               func(context.Context)
	workerUntil                                                                  time.Time
	lastRead                                                                     *bridgeReadFake
}

func (f *bridgeFixture) next() string {
	f.serial++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", f.serial)
}
func (f *bridgeFixture) refresh(now time.Time) {
	f.now = now
	until := now.Add(4 * time.Second)
	f.i.VerifiedAt, f.i.ValidUntil = now, until
	f.a.CheckedAt, f.a.ValidUntil = now, until
	f.a.Environment.ObservedAt, f.a.Environment.ValidUntil = now, until
	f.a.Environment.Recovery.ObservedAt, f.a.Environment.Recovery.FreshUntil = now, until
	f.a.Environment.Processing.ObservedAt, f.a.Environment.Processing.ValidUntil = now, until
	f.a.Retention.ObservedAt, f.a.Retention.ValidUntil = now, until
	f.p.ObservedAt, f.p.ValidUntil = now, until
}
func newBridgeFixture(t *testing.T) *bridgeFixture {
	t.Helper()
	f := &bridgeFixture{now: time.Now().UTC().Truncate(time.Microsecond), queryFresh: true, batchFresh: true, claimFresh: true, ready: true}
	rev := identity.Revision{UID: bridgeID, Generation: 1, Digest: [32]byte{1}}
	principal := identity.Principal{Issuer: "https://issuer.example", Subject: "developer", ClientID: "client", Kind: identity.Human}
	location := artifact.Location{ClusterID: bridgeID, ArtifactID: bridgeID, AttemptID: bridgeID}
	scope := value.ContextProjectionScope{RootID: bridgeID, CaseID: bridgeID, ArtifactID: bridgeID, CaptureID: bridgeID, ClusterID: bridgeID,
		NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, SourceProjectionDigest: value.ContextSourceProjectionDigest(),
		SourceFormat: artifact.ContextFormat, DisplayVersion: value.ContextDisplayVersion, Selection: value.LineSelection{LineStart: 1, MaxLines: 200}, Principal: principal}
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: bridgeID, TargetClusterID: bridgeID, StoreID: bridgeID,
		StorageRegion: "region", AcquisitionClusterID: bridgeID, AcquisitionRegion: "region", ConnectorClusterID: bridgeID, ConnectorRegion: "region",
		HubClusterID: bridgeID, HubRegion: "region", WorkerConfiguration: rev, HubConfiguration: rev}
	f.a = value.ContextProjectionAuthority{Scope: scope, Environment: value.ContextProjectionEnvironment{RootID: bridgeID, InstallationID: bridgeID,
		Region: "region", StoreID: bridgeID, Location: location, Principal: principal, PolicyRevision: rev, Path: path,
		Recovery:   artifact.RecoveryProof{InstallationID: bridgeID, IssuerEpoch: bridgeID, Revision: rev},
		Processing: artifact.DownloadProcessingProof{RootID: bridgeID, Epoch: bridgeID, CaptureID: bridgeID, Location: location, Sequence: 1, StateDigest: artifact.Digest{1}}},
		Retention: artifact.RetentionProof{RootID: bridgeID, ClusterID: bridgeID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod",
			Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1}, PermissionRevision: rev, IdentityRevision: rev, DecisionDigest: artifact.Digest{1},
		AccessUntil: f.now.Add(time.Minute), DeleteBy: f.now.Add(2 * time.Minute)}
	f.a.Retention.Sources[0] = artifact.RetentionSourceVersion{ClusterID: bridgeID, ControlNamespaceUID: "control", Epoch: bridgeID, Hub: true,
		ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}
	f.i = identity.Identity{Principal: principal, Policy: rev, Scopes: []string{"evidence:read"}, Groups: []string{"team"}}
	f.p = value.ContextQueryPlan{AcceptanceID: bridgeID, AccountID: bridgeID, AllocationID: bridgeID, RootID: bridgeID, InstallationID: bridgeID,
		ClusterID: bridgeID, NamespaceUID: "namespace", WorkloadUID: "workload", AllocationRevision: 1, PoolSource: rev, PolicySource: rev, Principal: principal,
		Profile: value.ContextQueryResourceProfile{ID: bridgeID, Source: rev, Qualification: rev, Path: path, Lifetime: value.ContextDefaultQueryTime,
			Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10,
				ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
			Cost: value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * value.ContextBatchReadWork, StructuredBytes: 2 * value.ContextResultBytes,
				WireBytes: 2 * value.ContextWireBytes, UnwrapAttempts: 6, ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2, AuditObjects: 20,
				SQLRows: 20, SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}, PollLimit: 4, ControlTransitionLimit: 32},
		HardUntil: f.now.Add(time.Minute), EffectsUntil: f.now.Add(3 * time.Minute), CleanupUntil: f.now.Add(4 * time.Minute), RetireBy: f.now.Add(time.Hour)}
	f.refresh(f.now)
	f.s = analysisapp.ContextProjectionService{Results: analysisapp.ContextProjectionResults{RootID: bridgeID, InstallationID: bridgeID, HubProcessEpoch: bridgeID,
		Authority: f, Ledger: f, Reader: f, Now: func() time.Time { return f.now }, NewID: f.next}, Recovery: f, Routes: f, Plans: f, Workers: f}
	if !f.a.Valid(f.now) || !f.p.Valid(f.a.Scope, f.now) {
		t.Fatal("invalid fixture")
	}
	return f
}
func (f *bridgeFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx.Err() != nil {
		return identity.Identity{}, ctx.Err()
	}
	return f.i, nil
}
func (f *bridgeFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.a.Environment.Recovery, nil
}
func (f *bridgeFixture) ResolveContextProjection(ctx context.Context, _ value.ContextExcerptSelection, _ identity.Identity, _ artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	if f.routeHook != nil {
		f.routeHook(ctx)
	}
	return f.a.Scope.Candidate(), nil
}
func (f *bridgeFixture) ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error) {
	return f.a, nil
}
func (f *bridgeFixture) CheckProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionScope) (value.ContextProjectionAuthority, error) {
	if f.authorityHook != nil {
		f.authorityHook()
	}
	return f.a, nil
}
func (f *bridgeFixture) ContextQueryPlan(ctx context.Context, _ value.ContextProjectionAuthority) (value.ContextQueryPlan, error) {
	if f.planHook != nil {
		f.planHook(ctx)
	}
	return f.p, nil
}
func (f *bridgeFixture) AdmitQuery(_ context.Context, q value.ContextQuery, _ value.ContextQueryRequest, _ value.ContextProjectionAuthority) (analysisapp.ContextQueryAdmission, error) {
	f.admissions++
	f.q = q
	return analysisapp.ContextQueryAdmission{Query: q, Fresh: f.queryFresh}, f.queryErr
}
func (f *bridgeFixture) LookupQuery(context.Context, identity.Principal, string) (value.ContextQuery, error) {
	return f.q, nil
}
func (f *bridgeFixture) AdmitQueryPoll(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error {
	f.polls++
	if int64(f.polls) > f.q.Plan.Profile.PollLimit {
		return value.ErrUnavailable
	}
	return nil
}
func (f *bridgeFixture) PermitQuery(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error {
	return f.permitErr
}
func (f *bridgeFixture) BeginReadBatch(_ context.Context, q value.ContextQuery, r value.ContextQueryRequest, w value.ContextQueryWorker, id string, a value.ContextProjectionAuthority) (analysisapp.ContextQueryBatchAdmission, error) {
	if f.active || f.batches >= value.ContextMaxReadBatches {
		return analysisapp.ContextQueryBatchAdmission{}, value.ErrUnavailable
	}
	f.batches++
	f.active = true
	b := value.ContextReadBatch{QueryID: q.ID, ID: id, OperationID: r.Call.ID, Generation: int64(f.batches), Worker: w, Request: r, StartedAt: f.now,
		Until: identity.Earlier(q.Deadline, a.ValidUntil), CleanupUntil: q.CleanupUntil}
	return analysisapp.ContextQueryBatchAdmission{Batch: b, Fresh: f.batchFresh}, nil
}
func (f *bridgeFixture) ClaimReadBatch(ctx context.Context, b value.ContextReadBatch, _ value.ContextProjectionAuthority) (value.ContextReadStart, error) {
	f.claims++
	if f.claimHook != nil {
		f.claimHook(ctx)
	}
	return value.ContextReadStart{Batch: b, ClaimID: f.next(), Fresh: f.claimFresh}, f.claimErr
}
func (f *bridgeFixture) PermitReadBatch(context.Context, value.ContextReadBatch, value.ContextProjectionAuthority) error {
	return f.permitErr
}
func (f *bridgeFixture) CompleteReadBatch(ctx context.Context, b value.ContextReadBatch, closed analysisapp.ContextProjectionClosed) error {
	return closed.WithProjectionClosed(ctx, b, func(context.Context) error { f.completions++; f.active = false; return nil })
}
func (f *bridgeFixture) AdmitProjectionWorker(context.Context, value.ContextQuery, analysisapp.ContextProjectionRequestOwner) error {
	f.starts++
	return nil
}
func (f *bridgeFixture) ObserveProjectionWorker(_ context.Context, q value.ContextQuery, _ analysisapp.ContextProjectionRequestOwner) (analysisapp.ContextProjectionWorkerObservation, error) {
	f.observations++
	if f.observeHook != nil {
		f.observeHook()
	}
	o := analysisapp.ContextProjectionWorkerObservation{Ready: f.ready, ObservedAt: f.now, ValidUntil: f.now.Add(4 * time.Second)}
	if !f.workerUntil.IsZero() {
		o.ValidUntil = f.workerUntil
	}
	if f.ready {
		o.Worker = value.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: bridgeID, PodUID: bridgeID, ProcessEpoch: bridgeID,
			Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	}
	return o, nil
}
func (f *bridgeFixture) ReadProjection(_ context.Context, start value.ContextReadStart, _ analysisapp.ContextProjectionRequestOwner) (analysisapp.ContextProjectionRead, error) {
	f.reads++
	f.lastRead = &bridgeReadFake{batch: start.Batch, projection: bridgeProjection(f.now), closeErr: f.closeErr}
	return f.lastRead, f.errorAfterRead
}

type bridgeReadFake struct {
	batch        value.ContextReadBatch
	projection   value.PodStatusProjection
	closed       bool
	closeErr     error
	cleanupUntil time.Time
}

func (r *bridgeReadFake) Projection(context.Context) (value.PodStatusProjection, error) {
	return r.projection, nil
}
func (r *bridgeReadFake) CheckCurrent(context.Context) error {
	if r.closed {
		return value.ErrUnavailable
	}
	return nil
}
func (r *bridgeReadFake) Close(ctx context.Context) error {
	r.cleanupUntil, _ = ctx.Deadline()
	r.closed = true
	return r.closeErr
}
func (r *bridgeReadFake) WithProjectionClosed(ctx context.Context, b value.ContextReadBatch, next func(context.Context) error) error {
	if !r.closed || r.closeErr != nil || !r.batch.Equal(b) || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return next(ctx)
}

func bridgeProjection(now time.Time) value.PodStatusProjection {
	return value.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: "namespace", PodUID: "pod",
		ResourceVersion: "7", ObservedAt: now, Phase: "Running", Ready: "True", Initialized: "True",
		Scheduled: "True", RuntimeInstances: 1, Running: 1}
}
