package analysis

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

const projectionID = "11111111-1111-4111-8111-111111111111"

// All authorities/backing below are explicit component fakes. They exercise
// composition ordering and uncertainty, not production SQL/C-07/C-08/C-14 proof.
type projectionFixture struct {
	now                                                                          time.Time
	serial                                                                       int
	a                                                                            value.ContextProjectionAuthority
	i                                                                            identity.Identity
	p                                                                            value.ContextQueryPlan
	q                                                                            value.ContextQuery
	s                                                                            ContextProjectionService
	admissions, starts, polls, observations, batches, claims, reads, completions int
	active                                                                       bool
	queryFresh, batchFresh, claimFresh, ready                                    bool
	queryErr, claimErr, closeErr, permitErr, errorAfterRead                      error
	authorityReads                                                               int
	authorityErr                                                                 error
	authorityHook                                                                func()
	observeHook                                                                  func()
	routeHook, planHook, claimHook                                               func(context.Context)
	workerUntil                                                                  time.Time
	lastRead                                                                     *projectionReadFake
	// frames simulates the hub's per-frame native gate: each frame consults the
	// request owner and an independent SQL operation/row fence (frameErr).
	frames, frameChecks int
	frameErr            error
	frameHook           func(int)
}

func (f *projectionFixture) next() string {
	f.serial++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", f.serial)
}
func (f *projectionFixture) refresh(now time.Time) {
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
func newProjectionFixture(t *testing.T) *projectionFixture {
	t.Helper()
	f := &projectionFixture{now: time.Now().UTC().Truncate(time.Microsecond), queryFresh: true, batchFresh: true, claimFresh: true, ready: true}
	rev := identity.Revision{UID: projectionID, Generation: 1, Digest: [32]byte{1}}
	principal := identity.Principal{Issuer: "https://issuer.example", Subject: "developer", ClientID: "client", Kind: identity.Human}
	location := artifact.Location{ClusterID: projectionID, ArtifactID: projectionID, AttemptID: projectionID}
	scope := value.ContextProjectionScope{RootID: projectionID, CaseID: projectionID, ArtifactID: projectionID, CaptureID: projectionID, ClusterID: projectionID,
		NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{2}, SourceProjectionDigest: value.ContextSourceProjectionDigest(),
		SourceFormat: artifact.ContextFormat, DisplayVersion: value.ContextDisplayVersion, Selection: value.LineSelection{LineStart: 1, MaxLines: 200}, Principal: principal}
	path := value.ContextProjectionPath{Purpose: value.ContextProjectionPurpose, ID: projectionID, TargetClusterID: projectionID, StoreID: projectionID,
		StorageRegion: "region", AcquisitionClusterID: projectionID, AcquisitionRegion: "region", ConnectorClusterID: projectionID, ConnectorRegion: "region",
		HubClusterID: projectionID, HubRegion: "region", WorkerConfiguration: rev, HubConfiguration: rev}
	f.a = value.ContextProjectionAuthority{Scope: scope, Environment: value.ContextProjectionEnvironment{RootID: projectionID, InstallationID: projectionID,
		Region: "region", StoreID: projectionID, Location: location, Principal: principal, PolicyRevision: rev, Path: path,
		Recovery:   artifact.RecoveryProof{InstallationID: projectionID, IssuerEpoch: projectionID, Revision: rev},
		Processing: artifact.DownloadProcessingProof{RootID: projectionID, Epoch: projectionID, CaptureID: projectionID, Location: location, Sequence: 1, StateDigest: artifact.Digest{1}}},
		Retention: artifact.RetentionProof{RootID: projectionID, ClusterID: projectionID, NamespaceUID: "namespace", WorkloadUID: "workload", PodUID: "pod",
			Topology: rev, Policy: rev, Selectors: rev, SourceCount: 1}, PermissionRevision: rev, IdentityRevision: rev, DecisionDigest: artifact.Digest{1},
		AccessUntil: f.now.Add(time.Minute), DeleteBy: f.now.Add(2 * time.Minute)}
	f.a.Retention.Sources[0] = artifact.RetentionSourceVersion{ClusterID: projectionID, ControlNamespaceUID: "control", Epoch: projectionID, Hub: true,
		ProtectionDigest: artifact.Digest{1}, SnapshotDigest: artifact.Digest{2}, Acceptance: rev}
	f.i = identity.Identity{Principal: principal, Policy: rev, Scopes: []string{"evidence:read"}, Groups: []string{"team"}}
	f.p = value.ContextQueryPlan{AcceptanceID: projectionID, AccountID: projectionID, AllocationID: projectionID, RootID: projectionID, InstallationID: projectionID,
		ClusterID: projectionID, NamespaceUID: "namespace", WorkloadUID: "workload", AllocationRevision: 1, PoolSource: rev, PolicySource: rev, Principal: principal,
		Profile: value.ContextQueryResourceProfile{ID: projectionID, Source: rev, Qualification: rev, Path: path, Lifetime: value.ContextDefaultQueryTime,
			Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10,
				ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
			Cost: value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * value.ContextBatchReadWork, StructuredBytes: 2 * value.ContextResultBytes,
				WireBytes: 2 * value.ContextWireBytes, UnwrapAttempts: 6, ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2, AuditObjects: 20,
				SQLRows: 20, SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}, PollLimit: 4, ControlTransitionLimit: 32},
		HardUntil: f.now.Add(time.Minute), EffectsUntil: f.now.Add(3 * time.Minute), CleanupUntil: f.now.Add(4 * time.Minute), RetireBy: f.now.Add(time.Hour)}
	f.refresh(f.now)
	f.s = ContextProjectionService{Results: ContextProjectionResults{RootID: projectionID, InstallationID: projectionID, HubProcessEpoch: projectionID,
		Authority: f, Ledger: f, Reader: f, Now: func() time.Time { return f.now }, NewID: f.next}, Recovery: f, Routes: f, Plans: f, Workers: f}
	if !f.a.Valid(f.now) || !f.p.Valid(f.a.Scope, f.now) {
		t.Fatal("invalid fixture")
	}
	return f
}
func (f *projectionFixture) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if ctx.Err() != nil {
		return identity.Identity{}, ctx.Err()
	}
	return f.i, nil
}
func (f *projectionFixture) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	return f.a.Environment.Recovery, nil
}
func (f *projectionFixture) ResolveContextProjection(ctx context.Context, _ value.ContextExcerptSelection, _ identity.Identity, _ artifact.RecoveryProof) (value.ContextProjectionCandidate, error) {
	if f.routeHook != nil {
		f.routeHook(ctx)
	}
	return f.a.Scope.Candidate(), nil
}
func (f *projectionFixture) ResolveProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionCandidate) (value.ContextProjectionAuthority, error) {
	f.authorityReads++
	return f.a, f.authorityErr
}
func (f *projectionFixture) CheckProjectionCurrent(context.Context, identities.CurrentIdentity, value.ContextProjectionScope) (value.ContextProjectionAuthority, error) {
	f.authorityReads++
	if f.authorityHook != nil {
		f.authorityHook()
	}
	return f.a, f.authorityErr
}
func (f *projectionFixture) ContextQueryPlan(ctx context.Context, _ value.ContextProjectionAuthority) (value.ContextQueryPlan, error) {
	if f.planHook != nil {
		f.planHook(ctx)
	}
	return f.p, nil
}
func (f *projectionFixture) AdmitQuery(_ context.Context, q value.ContextQuery, _ value.ContextQueryRequest, _ value.ContextProjectionAuthority) (ContextQueryAdmission, error) {
	f.admissions++
	f.q = q
	return ContextQueryAdmission{Query: q, Fresh: f.queryFresh}, f.queryErr
}
func (f *projectionFixture) LookupQuery(context.Context, identity.Principal, string) (value.ContextQuery, error) {
	return f.q, nil
}
func (f *projectionFixture) AdmitQueryPoll(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error {
	f.polls++
	if int64(f.polls) > f.q.Plan.Profile.PollLimit {
		return value.ErrUnavailable
	}
	return nil
}
func (f *projectionFixture) PermitQuery(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextProjectionAuthority) error {
	return f.permitErr
}
func (f *projectionFixture) BeginReadBatch(_ context.Context, q value.ContextQuery, r value.ContextQueryRequest, w value.ContextQueryWorker, id string, a value.ContextProjectionAuthority) (ContextQueryBatchAdmission, error) {
	if f.permitErr != nil {
		return ContextQueryBatchAdmission{}, f.permitErr
	}
	if f.active || f.batches >= value.ContextMaxReadBatches {
		return ContextQueryBatchAdmission{}, value.ErrUnavailable
	}
	f.batches++
	f.active = true
	b := value.ContextReadBatch{QueryID: q.ID, ID: id, OperationID: r.Call.ID, Generation: int64(f.batches), Worker: w, Request: r, StartedAt: f.now,
		Until: identity.Earlier(q.Deadline, a.ValidUntil), CleanupUntil: q.CleanupUntil}
	return ContextQueryBatchAdmission{Batch: b, Fresh: f.batchFresh}, nil
}
func (f *projectionFixture) ClaimReadBatch(ctx context.Context, b value.ContextReadBatch, _ value.ContextProjectionAuthority) (value.ContextReadStart, error) {
	f.claims++
	if f.claimHook != nil {
		f.claimHook(ctx)
	}
	return value.ContextReadStart{Batch: b, ClaimID: f.next(), Fresh: f.claimFresh}, f.claimErr
}
func (f *projectionFixture) PermitReadBatch(context.Context, value.ContextReadBatch, value.ContextProjectionAuthority) error {
	return f.permitErr
}
func (f *projectionFixture) CompleteReadBatch(ctx context.Context, b value.ContextReadBatch, closed ContextProjectionClosed) error {
	return closed.WithProjectionClosed(ctx, b, func(context.Context) error { f.completions++; f.active = false; return nil })
}
func (f *projectionFixture) AdmitProjectionWorker(context.Context, value.ContextQuery, ContextProjectionRequestOwner) error {
	f.starts++
	return nil
}
func (f *projectionFixture) ObserveProjectionWorker(_ context.Context, q value.ContextQuery, _ ContextProjectionRequestOwner) (ContextProjectionWorkerObservation, error) {
	f.observations++
	if f.observeHook != nil {
		f.observeHook()
	}
	o := ContextProjectionWorkerObservation{Ready: f.ready, ObservedAt: f.now, ValidUntil: f.now.Add(4 * time.Second)}
	if !f.workerUntil.IsZero() {
		o.ValidUntil = f.workerUntil
	}
	if f.ready {
		o.Worker = value.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: projectionID, PodUID: projectionID, ProcessEpoch: projectionID,
			Certificate: artifact.Digest{1}, Configuration: q.Plan.Profile.Path.WorkerConfiguration}
	}
	return o, nil
}
func (f *projectionFixture) ReadProjection(ctx context.Context, start value.ContextReadStart, owner ContextProjectionRequestOwner) (ContextProjectionRead, error) {
	f.reads++
	for n := 0; n < f.frames; n++ {
		if f.frameHook != nil {
			f.frameHook(n)
		}
		if _, err := owner.CheckCurrent(ctx); err != nil {
			return nil, err
		}
		if f.frameErr != nil {
			return nil, f.frameErr
		}
		f.frameChecks++
	}
	f.lastRead = &projectionReadFake{batch: start.Batch, projection: displayProjection(), closeErr: f.closeErr}
	return f.lastRead, f.errorAfterRead
}

type projectionReadFake struct {
	batch        value.ContextReadBatch
	projection   value.PodStatusProjection
	closed       bool
	closeErr     error
	cleanupUntil time.Time
}

func (r *projectionReadFake) Projection(context.Context) (value.PodStatusProjection, error) {
	return r.projection, nil
}
func (r *projectionReadFake) CheckCurrent(context.Context) error {
	if r.closed {
		return value.ErrUnavailable
	}
	return nil
}
func (r *projectionReadFake) Close(ctx context.Context) error {
	r.cleanupUntil, _ = ctx.Deadline()
	r.closed = true
	return r.closeErr
}
func (r *projectionReadFake) WithProjectionClosed(ctx context.Context, b value.ContextReadBatch, next func(context.Context) error) error {
	if !r.closed || r.closeErr != nil || !r.batch.Equal(b) || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return next(ctx)
}

type projectionInvocationFake struct {
	call           value.ContextQueryCall
	input          ContextQueryInput
	outcome        *ContextProjectionDelivery
	intentErr      error
	invocationHook func(context.Context)
}

func (i *projectionInvocationFake) Invocation(ctx context.Context) (value.ContextQueryCall, error) {
	if i.invocationHook != nil {
		i.invocationHook(ctx)
	}
	return i.call, nil
}
func (i *projectionInvocationFake) CheckInput(_ context.Context, in ContextQueryInput) error {
	if in != i.input {
		return value.ErrUnavailable
	}
	return nil
}
func (i *projectionInvocationFake) CheckIntent(_ context.Context, call value.ContextQueryCall) error {
	if call != i.call {
		return value.ErrUnavailable
	}
	return i.intentErr
}
func (i *projectionInvocationFake) CheckOutcome(_ context.Context, d *ContextProjectionDelivery) error {
	if i.outcome != d {
		return value.ErrUnavailable
	}
	return nil
}
func (f *projectionFixture) invocation(tool string) *projectionInvocationFake {
	i := &projectionInvocationFake{call: value.ContextQueryCall{ID: f.next(), RootID: projectionID, Tool: tool, InputFormat: "context-query-input/v1", MACVersion: "v1",
		InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: f.i.Principal, StartedAt: f.now, Until: f.now.Add(4 * time.Second), WriteUntil: f.now.Add(30 * time.Second)}}
	if tool == "get_file_excerpt" {
		i.input.Selection = value.ContextExcerptSelection{CaseID: f.a.Scope.CaseID, ArtifactID: f.a.Scope.ArtifactID, Selection: f.a.Scope.Selection}
	} else {
		i.input.QueryID = f.q.ID
	}
	return i
}
func (f *projectionFixture) begin(t *testing.T) (*ContextProjectionDelivery, *projectionInvocationFake) {
	t.Helper()
	i := f.invocation("get_file_excerpt")
	d, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection)
	if err != nil {
		t.Fatal(err)
	}
	return d, i
}

func TestQueryAdmissionAndReadRequireOriginalAcknowledgedIntent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*projectionFixture, *projectionInvocationFake)
	}{
		{"unaudited", func(f *projectionFixture, i *projectionInvocationFake) { i.intentErr = value.ErrUnavailable }},
		{"wrong-input", func(f *projectionFixture, i *projectionInvocationFake) { i.input.Selection.Selection.LineStart = 2 }},
		{"missing-qualified-dimension", func(f *projectionFixture, i *projectionInvocationFake) { f.p.Profile.Cost.BackupBytes = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProjectionFixture(t)
			i := f.invocation("get_file_excerpt")
			selection := value.ContextExcerptSelection{CaseID: f.a.Scope.CaseID, ArtifactID: f.a.Scope.ArtifactID, Selection: f.a.Scope.Selection}
			tc.change(f, i)
			if _, err := f.s.BeginExcerpt(context.Background(), f, i, selection); err == nil {
				t.Fatal("invalid prerequisite accepted")
			}
			if f.admissions+f.starts+f.reads != 0 {
				t.Fatal("effect before prerequisites", f.admissions, f.starts, f.reads)
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*projectionFixture)
	}{
		{"replayed-admission", func(f *projectionFixture) { f.queryFresh = false }},
		{"unknown-admission", func(f *projectionFixture) { f.queryErr = errors.New("commit reply lost") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProjectionFixture(t)
			tc.change(f)
			i := f.invocation("get_file_excerpt")
			if _, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection); err == nil {
				t.Fatal("unknown/replayed admission dispatched")
			}
			if f.starts+f.reads != 0 {
				t.Fatal("admission replay started work")
			}
		})
	}
}

func TestQueryDeliveryRemainsActiveThroughExactOutcomeAndJoinedClose(t *testing.T) {
	f := newProjectionFixture(t)
	d, i := f.begin(t)
	if f.starts != 1 || f.reads != 1 || !f.active || f.completions != 0 {
		t.Fatal("missing owned active batch")
	}
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("disclosed before exact outcome acknowledgement")
	}
	x, ok := d.Excerpt()
	if !ok || len(x.Lines) != 14 {
		t.Fatal("missing fixed projection")
	}
	original := x.Lines[0]
	x.Lines[0] = "mutated"
	x, _ = d.Excerpt()
	if x.Lines[0] != original {
		t.Fatal("caller mutated retained result")
	}
	i.outcome = d
	if err := d.CheckDisclosure(context.Background()); err != nil {
		t.Fatal(err)
	}
	poll := f.invocation("get_query_result")
	if _, err := f.s.Results.GetQueryResult(context.Background(), f, poll, f.q.ID); err == nil {
		t.Fatal("second batch started during outward delivery")
	}
	if f.reads != 1 || f.batches != 1 || f.starts != 1 {
		t.Fatal("passive poll dispatched or overlapped")
	}
	cleanup, cancel := context.WithDeadline(context.Background(), i.call.WriteUntil)
	defer cancel()
	if err := d.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	if f.active || f.completions != 1 || !f.lastRead.closed || f.batches != 1 {
		t.Fatal("joined close lost accounting")
	}
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("closed delivery remained readable")
	}
	if _, ok := d.Excerpt(); ok {
		t.Fatal("closed delivery retained lines")
	}
	if err := d.Close(cleanup); err != nil || f.completions != 1 {
		t.Fatal("close repeated SQL transition")
	}
}

func TestQueryLostOutwardReplyUsesFreshPaidBatchWithoutNewWorker(t *testing.T) {
	f := newProjectionFixture(t)
	d, _ := f.begin(t)
	original := f.q
	// No outward receipt is assumed. Positive private/hub close is sufficient
	// for a second paid batch; previous read/key spend remains consumed.
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.refresh(f.now.Add(5 * time.Second))
	i := f.invocation("get_query_result")
	d2, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID)
	if err != nil {
		t.Fatal("fresh current request could not read original unexpired query", err)
	}
	if f.starts != 1 || f.reads != 2 || f.batches != 2 || !f.q.Equal(original) || d2.association.Generation != 2 {
		t.Fatal("retry reset worker/query/spend")
	}
	i.outcome = d2
	if err = d2.CheckDisclosure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = d2.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	i = f.invocation("get_query_result")
	if _, err = f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID); err == nil {
		t.Fatal("third batch admitted")
	}
	if f.reads != 2 || f.starts != 1 {
		t.Fatal("exhausted read repaired worker")
	}
}

func TestQueryUncertainPrivateCloseAndUnknownStartStayCharged(t *testing.T) {
	f := newProjectionFixture(t)
	f.closeErr = errors.New("private closure unknown")
	d, _ := f.begin(t)
	if d.Close(context.Background()) == nil || !f.active || f.completions != 0 {
		t.Fatal("uncertain close released batch")
	}
	f.refresh(f.now.Add(5 * time.Second))
	i := f.invocation("get_query_result")
	if _, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID); err == nil {
		t.Fatal("lease expiry substituted for joined private closure")
	}
	if f.reads != 1 || f.starts != 1 || f.batches != 1 {
		t.Fatal("uncertain work restarted")
	}
	for _, tc := range []struct {
		name   string
		change func(*projectionFixture)
	}{
		{"batch-replay", func(f *projectionFixture) { f.batchFresh = false }},
		{"claim-replay", func(f *projectionFixture) { f.claimFresh = false }},
		{"claim-unknown", func(f *projectionFixture) { f.claimErr = errors.New("claim commit unknown") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProjectionFixture(t)
			tc.change(f)
			i := f.invocation("get_file_excerpt")
			if _, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection); err == nil {
				t.Fatal("uncertain/repeated start accepted")
			}
			if f.reads != 0 || !f.active || f.batches != 1 {
				t.Fatal("unknown claim refunded or executed")
			}
		})
	}
}

func TestQueryPendingPollCannotDispatchAndRequiresOutcomeGuard(t *testing.T) {
	f := newProjectionFixture(t)
	f.ready = false
	d, i := f.begin(t)
	if !d.Pending() || f.starts != 1 || f.batches != 0 || d.Effect() != ContextQueryAdmitted {
		t.Fatal("wrong pending disposition")
	}
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("pending handle bypassed outcome audit")
	}
	i.outcome = d
	if err := d.CheckDisclosure(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = d.Close(context.Background())
	i = f.invocation("get_query_result")
	next, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID)
	if err != nil || !next.Pending() || f.starts != 1 || f.polls != 1 || next.Effect() != ContextQueryPollCharged {
		t.Fatal("poll dispatched new worker or omitted finite accounting", err)
	}
	_ = next.Close(context.Background())
}

func TestQueryRequestObservationAndCurrentSQLFence(t *testing.T) {
	// ADR219 retains one exact observation inside this request. Changed external
	// facts are evaluated by the next request; SQL effects still deny immediately.
	for _, tc := range []struct {
		name   string
		mutate func(*projectionFixture)
	}{
		{"group-revocation", func(f *projectionFixture) { f.i.Groups = []string{"different"}; f.authorityErr = value.ErrUnavailable }},
		{"source-replacement", func(f *projectionFixture) { f.a.Scope.Version[0]++ }},
		{"retention-cutoff", func(f *projectionFixture) { f.a.AccessUntil = f.now }},
		{"recovery-change", func(f *projectionFixture) { f.a.Environment.Recovery.Revision.Generation++ }},
		{"path-change", func(f *projectionFixture) { f.a.Environment.Path.WorkerConfiguration.Generation++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProjectionFixture(t)
			d, i := f.begin(t)
			i.outcome = d
			original, err := d.owner.CheckCurrent(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(f)
			retained, err := d.owner.CheckCurrent(context.Background())
			if err != nil || retained != original || d.CheckDisclosure(context.Background()) != nil || f.authorityReads != 1 {
				t.Fatal("request rebuilt or changed its original observation", err, f.authorityReads)
			}
			if err = d.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			next := f.invocation("get_query_result")
			if result, err := f.s.Results.GetQueryResult(context.Background(), f, next, f.q.ID); err == nil || result != nil || f.authorityReads != 2 {
				t.Fatal("new poll reused prior request authority", err, f.authorityReads)
			}
		})
	}
	f := newProjectionFixture(t)
	d, i := f.begin(t)
	i.outcome = d
	f.permitErr = value.ErrUnavailable
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("current SQL fence bypassed")
	}
	_ = d.Close(context.Background())
}

func TestQueryOriginalRequestCancellation(t *testing.T) {
	f := newProjectionFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	i := f.invocation("get_file_excerpt")
	d, err := f.s.BeginExcerpt(ctx, f, i, i.input.Selection)
	if err != nil {
		t.Fatal(err)
	}
	i.outcome = d
	cancel()
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("Background detached original request cancellation")
	}
	cleanup, done := context.WithDeadline(context.Background(), i.call.WriteUntil.Add(-time.Second))
	defer done()
	if err = d.Close(cleanup); err != nil {
		t.Fatal("prepaid restrictive completion denied after request cancellation", err)
	}
	if !f.lastRead.cleanupUntil.Equal(i.call.WriteUntil.Add(-time.Second)) {
		t.Fatal("cleanup renewed earlier caller deadline")
	}
}

func TestQueryRechecksAfterBlockingObservation(t *testing.T) {
	for _, mutate := range []func(*projectionFixture){
		func(f *projectionFixture) { f.now = f.a.ValidUntil },
		func(f *projectionFixture) { f.permitErr = value.ErrUnavailable },
	} {
		f := newProjectionFixture(t)
		f.observeHook = func() { mutate(f) }
		i := f.invocation("get_file_excerpt")
		if _, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection); err == nil {
			t.Fatal("stale observation started read")
		}
		if f.batches+f.reads != 0 {
			t.Fatal("read charged/started after blocking revocation")
		}
	}
}

func TestQueryEveryBlockingPortRetainsEarlierOriginalCutoff(t *testing.T) {
	for _, stage := range []string{"route", "plan", "claim"} {
		t.Run(stage, func(t *testing.T) {
			f := newProjectionFixture(t)
			cutoff := f.now.Add(80 * time.Millisecond)
			wait := func(ctx context.Context) {
				d, ok := ctx.Deadline()
				if !ok || !d.Equal(cutoff) {
					t.Errorf("%s received renewed deadline: %v", stage, d)
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Error("shortened proof failed to cancel blocking port")
				}
			}
			switch stage {
			case "route":
				f.a.Environment.Recovery.FreshUntil = cutoff
				f.routeHook = wait
			case "plan":
				f.a.ValidUntil = cutoff
				f.planHook = wait
			case "claim":
				f.workerUntil = cutoff
				f.claimHook = wait
			}
			i := f.invocation("get_file_excerpt")
			if _, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection); err == nil {
				t.Fatal("expired port returned usable result")
			}
			if f.reads != 0 {
				t.Fatal("private read started after blocked claim expired")
			}
		})
	}
}

func TestQueryRetainsIdentitySnapshotAgainstPortSliceReuse(t *testing.T) {
	f := newProjectionFixture(t)
	f.observeHook = func() { f.i.Groups[0] = "changed-in-place" }
	i := f.invocation("get_file_excerpt")
	d, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.owner.initial.Groups) != 1 || d.owner.initial.Groups[0] != "team" || f.authorityReads != 1 {
		t.Fatal("port slice rewrote the retained original identity")
	}
	if err = d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := f.invocation("get_query_result")
	d, err = f.s.Results.GetQueryResult(context.Background(), f, next, f.q.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close(context.Background())
	if d.owner.initial.Groups[0] != "changed-in-place" || f.authorityReads != 2 {
		t.Fatal("new request reused old identity instead of current observation")
	}
}

type projectionIdentityFunc func(context.Context) (identity.Identity, error)

func (f projectionIdentityFunc) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	return f(ctx)
}

func TestQueryInitialBlockingReadsAreBoundedBeforeTheyRun(t *testing.T) {
	t.Run("first-identity", func(t *testing.T) {
		f := newProjectionFixture(t)
		i := f.invocation("get_file_excerpt")
		called := false
		current := projectionIdentityFunc(func(ctx context.Context) (identity.Identity, error) {
			called = true
			until, ok := ctx.Deadline()
			if !ok || !until.Equal(f.now.Add(5*time.Second)) {
				t.Fatal("first identity read lacked original5s deadline", until)
			}
			return identity.Identity{}, value.ErrUnavailable
		})
		if _, err := f.s.BeginExcerpt(context.Background(), current, i, i.input.Selection); err == nil || !called || f.admissions != 0 {
			t.Fatal("invalid first identity boundary")
		}
	})
	t.Run("audit-lineage", func(t *testing.T) {
		f := newProjectionFixture(t)
		i := f.invocation("get_file_excerpt")
		until := f.now.Add(80 * time.Millisecond)
		f.i.ValidUntil = until
		i.invocationHook = func(ctx context.Context) {
			d, ok := ctx.Deadline()
			if !ok || !d.Equal(until) {
				t.Fatal("audit lineage read renewed identity bound", d)
			}
			<-ctx.Done()
		}
		if _, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection); err == nil || f.admissions != 0 {
			t.Fatal("expired lineage read admitted query")
		}
	})
}

func TestQueryExpiredPublicContextCannotActAsCleanupPermit(t *testing.T) {
	f := newProjectionFixture(t)
	d, _ := f.begin(t)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if d.Close(expired) == nil || f.completions != 0 || !f.active {
		t.Fatal("expired cleanup bound released charges")
	}
	// Normal transports supply their separately owned original prepaid cleanup
	// context, as tested after cancellation above. Neither expiry nor a later
	// Close retry may pretend this unknown transition completed.
	if d.Close(context.Background()) == nil || f.completions != 0 {
		t.Fatal("cleanup retry renewed original failed close")
	}
}

func TestQueryDeliveryTimingDoesNotRenewLatePollOrPreparedCutoff(t *testing.T) {
	f := newProjectionFixture(t)
	d, i := f.begin(t)
	if !d.QueryDeadline().Equal(f.q.Deadline) || !d.ObservedAt().Equal(f.now) || !d.CleanupUntil().Equal(i.call.WriteUntil) || !d.ValidUntil().Before(d.QueryDeadline()) {
		t.Fatal("query, observation, cleanup and request bounds were conflated")
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.refresh(f.now.Add(9 * time.Second))
	i = f.invocation("get_query_result")
	d, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.ObservedAt().Equal(f.now) || d.QueryDeadline().Sub(d.ObservedAt()) != time.Second {
		t.Fatal("late poll used query creation to renew remaining lifetime")
	}
	i.outcome = d
	if err = d.CheckDisclosure(context.Background()); err != nil {
		t.Fatal(err)
	}
	observed, deadline := d.ObservedAt(), d.QueryDeadline()
	f.a.AccessUntil = f.now.Add(500 * time.Millisecond)
	f.a.ValidUntil = f.a.AccessUntil
	// A restrictive SQL retention change is current even though this request
	// retains its original external observation.
	f.permitErr = value.ErrExpired
	if d.CheckDisclosure(context.Background()) == nil {
		t.Fatal("current SQL retention fence did not stop prepared disclosure")
	}
	if !d.ObservedAt().Equal(observed) || !d.QueryDeadline().Equal(deadline) {
		t.Fatal("audited prepared metadata mutated after observation")
	}
	_ = d.Close(context.Background())
}

func TestQueryDeliveryDoneTracksOriginalOwner(t *testing.T) {
	f := newProjectionFixture(t)
	d, _ := f.begin(t)
	select {
	case <-d.Done():
		t.Fatal("live owner already canceled")
	default:
	}
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.Done():
	default:
		t.Fatal("owner closure did not cancel transport observation")
	}
	var missing *ContextProjectionDelivery
	select {
	case <-missing.Done():
	default:
		t.Fatal("missing owner appears live")
	}
}

// native69: the first excerpt call returns pending while the worker starts;
// the full SQL permit fence runs before a read, not on the pending reply.
func TestQueryPendingReplySkipsPermitFence(t *testing.T) {
	f := newProjectionFixture(t)
	f.ready = false
	f.permitErr = value.ErrUnavailable
	i := f.invocation("get_file_excerpt")
	d, err := f.s.BeginExcerpt(context.Background(), f, i, i.input.Selection)
	if err != nil || !d.Pending() || f.batches != 0 {
		t.Fatal("pending reply ran the read permit", err)
	}
	_ = d.Close(context.Background())
}

// One public request reconstructs the complete projection authority once and
// reuses it through prepare, every native frame and disclosure (relaxed
// bounded cadence, AGENTS.md 2026-10-20). Row-level SQL fences still refuse
// the very next frame or disclosure without another reconstruction.
func TestQueryOneAuthorityPerRequestAcrossPrepareAndFrames(t *testing.T) {
	f := newProjectionFixture(t)
	d, _ := f.begin(t)
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.authorityReads, f.frames = 0, 8
	i := f.invocation("get_query_result")
	d2, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID)
	if err != nil {
		t.Fatal(err)
	}
	i.outcome = d2
	for range 3 {
		if err = d2.CheckDisclosure(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if f.authorityReads != 1 || f.frameChecks != 8 {
		t.Fatal("request reconstructed authority more than once", f.authorityReads, f.frameChecks)
	}
	// A SQL-level revocation (permission stream suspended, batch row no longer
	// current) is enforced immediately by the row fence, not by re-observation.
	f.permitErr = value.ErrUnavailable
	if d2.CheckDisclosure(context.Background()) == nil || f.authorityReads != 1 {
		t.Fatal("SQL revocation did not refuse the retained request immediately", f.authorityReads)
	}
	f.permitErr = nil
	_ = d2.Close(context.Background())
}

func TestQuerySQLFenceRefusesNextFrameWithinOneRequest(t *testing.T) {
	f := newProjectionFixture(t)
	d, _ := f.begin(t)
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.authorityReads, f.frames = 0, 8
	f.frameHook = func(n int) {
		if n == 3 {
			f.frameErr = value.ErrUnavailable // e.g. native operation/batch row revoked
		}
	}
	i := f.invocation("get_query_result")
	if out, err := f.s.Results.GetQueryResult(context.Background(), f, i, f.q.ID); err == nil || out != nil {
		t.Fatal("frame after SQL revocation was accepted")
	}
	if f.frameChecks != 3 || f.authorityReads != 1 {
		t.Fatal("revocation not enforced at the next frame", f.frameChecks, f.authorityReads)
	}
}
