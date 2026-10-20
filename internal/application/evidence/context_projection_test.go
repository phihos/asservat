package evidence

import (
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"testing"
	"time"
)

const projectionID = "11111111-1111-4111-8111-111111111111"
const projectionOtherID = "22222222-2222-4222-8222-222222222222"

// Explicit synthetic authorities isolate ordering/cancellation/spend only. They
// do not establish protected SQL, live Kubernetes proof or remote closure.
type projectionWorkerFixture struct {
	now                                time.Time
	a                                  value.ContextProjectionAuthority
	p                                  value.ContextQueryPlan
	q                                  value.ContextQuery
	w                                  value.ContextQueryWorker
	proof                              value.ContextProjectionWorkerProof
	start                              value.ContextReadStart
	source                             NativeContextSource
	worker                             *RegionalContextProjection
	opened, reads, keyCalls, closes    int
	openErr, closeErr, keyErr          error
	lastKey                            []byte
	closeHook                          func(context.Context)
	authorityHook, sourceHook, keyHook func(context.Context)
	nativeHook                         func(context.Context, KeyOpener) error
}

func newProjectionWorkerFixture(t *testing.T) *projectionWorkerFixture {
	t.Helper()
	f := &projectionWorkerFixture{now: time.Now().UTC().Truncate(time.Microsecond)}
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
	f.p = value.ContextQueryPlan{AcceptanceID: projectionID, AccountID: projectionID, AllocationID: projectionID, RootID: projectionID, InstallationID: projectionID,
		ClusterID: projectionID, NamespaceUID: "namespace", WorkloadUID: "workload", AllocationRevision: 1, PoolSource: rev, PolicySource: rev, Principal: principal,
		Profile: value.ContextQueryResourceProfile{ID: projectionID, Source: rev, Qualification: rev, Path: path, Lifetime: value.ContextDefaultQueryTime,
			Worker: value.ContextQueryWorkerLimits{CPUMilli: 100, MemoryBytes: 64 << 20, EphemeralStorageBytes: 4 << 20, WorkerTransientBytes: 8 << 20, HubTransientBytes: 128 << 10,
				ProviderConcurrency: 1, AuthenticationConcurrency: 1, Runtime: time.Minute, CredentialLifetime: 2 * time.Minute, ProviderEffectLifetime: time.Minute, Cleanup: time.Minute},
			Cost: value.ContextQueryCost{Workers: 1, ReadBatches: 2, ReadBytes: 2 * value.ContextBatchReadWork, StructuredBytes: 2 * value.ContextResultBytes,
				WireBytes: 2 * value.ContextWireBytes, UnwrapAttempts: 6, ProviderRequests: 20, AuthenticationRequests: 20, SigningAttempts: 2, AuditObjects: 20,
				SQLRows: 20, SQLBytes: 1 << 20, WALBytes: 1 << 20, BackupBytes: 1 << 20}, PollLimit: 4, ControlTransitionLimit: 32},
		HardUntil: f.now.Add(time.Minute), EffectsUntil: f.now.Add(3 * time.Minute), CleanupUntil: f.now.Add(4 * time.Minute), RetireBy: f.now.Add(time.Hour)}

	// Reuse only the neutral registered source/copy fixture, never its download grants.
	pub, _ := publicationTest(t)
	f.source = NativeContextSource{Expectation: pub.e, Copies: pub.copies}
	f.source.Expectation.ActionID = "pod-status"
	e := f.source.Expectation
	f.a.Scope.CaseID, f.a.Scope.CaptureID = e.CaseID, e.CaptureUID
	f.a.Scope.ArtifactID, f.a.Scope.ClusterID = e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	f.a.Scope.NamespaceUID, f.a.Scope.WorkloadUID, f.a.Scope.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	f.a.Scope.Version = ContextCopiesDigest(f.source.Copies)
	f.a.Environment.Location = e.Registration.Location
	f.a.Environment.StoreID = e.Registration.StoreID
	f.a.Environment.Path.StoreID = e.Registration.StoreID
	f.a.Environment.Path.TargetClusterID = e.Registration.Location.ClusterID
	f.a.Environment.Processing.Location = e.Registration.Location
	f.a.Environment.Processing.CaptureID = e.CaptureUID
	f.a.Retention.ClusterID, f.a.Retention.NamespaceUID, f.a.Retention.WorkloadUID, f.a.Retention.PodUID = f.a.Scope.ClusterID, e.NamespaceUID, e.WorkloadUID, e.PodUID
	f.a.AccessUntil, f.a.DeleteBy = e.Registration.ExpiresAt, e.Registration.DeleteBy
	f.p.ClusterID, f.p.NamespaceUID, f.p.WorkloadUID = f.a.Scope.ClusterID, e.NamespaceUID, e.WorkloadUID
	f.p.Profile.Path = f.a.Environment.Path
	until := f.now.Add(4 * time.Second)
	f.a.CheckedAt, f.a.ValidUntil = f.now, until
	f.a.Environment.ObservedAt, f.a.Environment.ValidUntil = f.now, until
	f.a.Environment.Recovery.ObservedAt, f.a.Environment.Recovery.FreshUntil = f.now, until
	f.a.Environment.Processing.ObservedAt, f.a.Environment.Processing.ValidUntil = f.now, until
	f.a.Retention.ObservedAt, f.a.Retention.ValidUntil = f.now, until
	f.p.ObservedAt, f.p.ValidUntil = f.now, until
	var err error
	f.q, err = value.NewContextQuery(projectionID, projectionID, projectionID, f.a, f.p, f.now)
	if err != nil {
		t.Fatal("query fixture", err)
	}
	f.w = value.ContextQueryWorker{QueryID: f.q.ID, WorkerID: f.q.WorkerID, PeerID: projectionID, PodUID: projectionID, ProcessEpoch: projectionID, Certificate: artifact.Digest{1}, Configuration: f.p.Profile.Path.WorkerConfiguration}
	f.proof = value.ContextProjectionWorkerProof{Binding: value.ContextProjectionWorkerBinding{QueryID: f.q.ID, WorkerID: f.w.WorkerID, InstallationID: projectionID, ClusterID: f.p.Profile.Path.AcquisitionClusterID, Namespace: "worker", NamespaceUID: "ns", ServiceAccount: "acquire", ServiceAccountUID: "sa", Job: "job", JobUID: "job-uid", Pod: "pod", PodUID: f.w.PodUID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}, Configuration: f.w.Configuration}, Peer: authorization.KeyPeer{InstallationID: projectionID, PeerID: f.w.PeerID, Role: "acquisition", Certificate: f.w.Certificate, NotBefore: f.now.Add(-time.Second), NotAfter: f.q.CredentialUntil}, ProcessEpoch: f.w.ProcessEpoch, PublicKey: artifact.Digest{1}, TokenDigest: artifact.Digest{2}, Protection: rev, ObservedAt: f.now, ValidUntil: until}
	request := value.ContextQueryRequest{Call: value.ContextQueryCall{ID: projectionID, RootID: f.q.Scope.RootID, Tool: "get_file_excerpt", InputFormat: "context-query-input/v1", MACVersion: "v1", InputDigest: artifact.Digest{1}, PrincipalDigest: artifact.Digest{2}, Principal: f.q.Scope.Principal, StartedAt: f.now, Until: until, WriteUntil: f.now.Add(30 * time.Second)}, OwnerID: projectionID, HubProcessEpoch: projectionID}
	f.start = value.ContextReadStart{ClaimID: projectionID, Fresh: true, Batch: value.ContextReadBatch{QueryID: f.q.ID, ID: projectionID, OperationID: request.Call.ID, Generation: 1, Worker: f.w, Request: request, StartedAt: f.now, Until: until, CleanupUntil: f.q.CleanupUntil}}
	f.worker, err = NewRegionalContextProjection(context.Background(), f.q, f.w, f, f, f, f, authorization.KeyScope{InstallationID: projectionID, Purpose: "artifact", KeyID: "context"}, time.Now)
	if err != nil || !f.proof.Matches(f.q, f.w, time.Now()) || !ProjectionSourceMatches(f.source, f.q, f.a) {
		t.Fatal("worker fixture", err)
	}
	t.Cleanup(f.worker.StopLocal)
	return f
}
func (f *projectionWorkerFixture) Request() value.ContextQueryRequest { return f.start.Batch.Request }
func (f *projectionWorkerFixture) CheckCurrent(ctx context.Context) (value.ContextProjectionAuthority, error) {
	if f.authorityHook != nil {
		f.authorityHook(ctx)
	}
	return f.a, ctx.Err()
}
func (f *projectionWorkerFixture) OpenProjectionExecution(_ context.Context, _ value.ContextQuery, _ value.ContextReadStart, _ ContextProjectionRequestOwner) (ContextProjectionExecution, error) {
	f.opened++
	return f, f.openErr
}
func (f *projectionWorkerFixture) WorkerProof() value.ContextProjectionWorkerProof { return f.proof }
func (f *projectionWorkerFixture) CloseExecution(ctx context.Context) error {
	f.closes++
	if f.closeHook != nil {
		f.closeHook(ctx)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return f.closeErr
}
func (f *projectionWorkerFixture) ReadProjectionSource(ctx context.Context, _ value.ContextQuery, _ value.ContextProjectionAuthority) (NativeContextSource, error) {
	if f.sourceHook != nil {
		f.sourceHook(ctx)
	}
	return f.source, ctx.Err()
}
func (f *projectionWorkerFixture) OpenProjectionKey(ctx context.Context, _ value.ContextProjectionKeyBinding, _ value.ContextProjectionKeyRole, _ artifact.SealedKey, _ []byte) ([]byte, error) {
	f.keyCalls++
	if f.keyHook != nil {
		f.keyHook(ctx)
	}
	f.lastKey = make([]byte, 32)
	for i := range f.lastKey {
		f.lastKey[i] = 7
	}
	if f.keyErr != nil {
		return f.lastKey, f.keyErr
	}
	return f.lastKey, ctx.Err()
}
func (f *projectionWorkerFixture) ReadProjectionNative(ctx context.Context, s NativeContextSource, _ value.ContextProjectionScope, keys KeyOpener, _ time.Time) (value.PodStatusProjection, error) {
	f.reads++
	if f.nativeHook != nil {
		if err := f.nativeHook(ctx, keys); err != nil {
			return value.PodStatusProjection{}, err
		}
	}
	for _, role := range []string{"manifest-key", "data-key", "index-key"} {
		aad, _ := ArtifactKeyBinding(s.Expectation.Binding(), role)
		key, err := keys.Open(ctx, artifact.SealedKey{Reference: "fixture", Ciphertext: "fixture"}, aad)
		clear(aad)
		clear(key)
		if err != nil {
			return value.PodStatusProjection{}, err
		}
	}
	return value.PodStatusProjection{Format: artifact.ContextFormat, NamespaceUID: s.Expectation.NamespaceUID, PodUID: s.Expectation.PodUID, ResourceVersion: "1", ObservedAt: f.now, Phase: "Running", Ready: "True", Initialized: "True", Scheduled: "True", RuntimeInstances: 1, Running: 1}, nil
}
func TestProjectionWorkerExactClaimBeforeProtectedOpen(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	wrong := f.start
	wrong.ClaimID = projectionOtherID
	if r, err := f.worker.ExecuteProjection(context.Background(), wrong, f); err == nil || r != nil || f.opened != 0 {
		t.Fatal("foreign claim reached execution", err, f.opened)
	}
}
func TestProjectionWorkerCallerCancellationBoundsBlockingAuthority(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.CloseLocal(context.Background())
	f.authorityHook = func(ctx context.Context) { <-ctx.Done() }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err = r.Projection(ctx); err == nil {
		t.Fatal("canceled read released projection")
	}
	if time.Since(started) > 300*time.Millisecond {
		t.Fatal("short caller cancellation lost during blocking proof")
	}
}
func TestProjectionWorkerUnknownOpenStillClosesKnownLocalHandle(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	f.openErr = errors.New("unknown open")
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err == nil || r == nil {
		t.Fatal("unknown start accepted")
	}
	if r.CloseLocal(context.Background()) == nil || f.closes != 1 || !f.worker.active {
		t.Fatal("unknown open lost cleanup or released worker", f.closes, f.worker.active)
	}
}

func TestProjectionWorkerThreeRolesAndTwoChargedBatches(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := r.Projection(context.Background()); err != nil || p.PodUID != f.q.Scope.PodUID || f.keyCalls != 3 {
		t.Fatal("missing approved projection/three roles", p, err, f.keyCalls)
	}
	second := f.start
	second.ClaimID = projectionOtherID
	second.Batch.ID = projectionOtherID
	second.Batch.Generation = 2
	if _, err = f.worker.ExecuteProjection(context.Background(), second, f); err == nil {
		t.Fatal("active batch allowed another read")
	}
	if err = r.CloseLocal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = f.worker.ExecuteProjection(context.Background(), f.start, f); err == nil {
		t.Fatal("spent generation executed again")
	}
	r, err = f.worker.ExecuteProjection(context.Background(), second, f)
	if err != nil {
		t.Fatal("second paid generation", err)
	}
	if err = r.CloseLocal(context.Background()); err != nil || f.keyCalls != 6 {
		t.Fatal("second batch key spend", err, f.keyCalls)
	}
	if _, err = r.Projection(context.Background()); err == nil {
		t.Fatal("closed local result disclosed")
	}
}
func TestProjectionWorkerOriginalProofBoundsBlockingSource(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	f.proof.ValidUntil = time.Now().Add(35 * time.Millisecond)
	f.sourceHook = func(ctx context.Context) {
		if d, _ := ctx.Deadline(); !d.Equal(f.proof.ValidUntil) {
			t.Error("source lost original proof deadline")
		}
		<-ctx.Done()
	}
	started := time.Now()
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err == nil || r == nil || f.reads != 0 || f.keyCalls != 0 || time.Since(started) > 300*time.Millisecond {
		t.Fatal("expired source lookup reached native read", err)
	}
	if err = r.CloseLocal(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestProjectionWorkerUnknownCloseNeverReleasesLocalWorker(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err != nil {
		t.Fatal(err)
	}
	f.closeErr = errors.New("unknown close")
	if r.CloseLocal(context.Background()) == nil || !f.worker.active {
		t.Fatal("unknown closure released worker")
	}
	f.closeErr = nil
	if r.CloseLocal(context.Background()) == nil || f.closes != 1 || !f.worker.active {
		t.Fatal("close retry replaced unknown result")
	}
}
func TestProjectionWorkerCleanupKeepsOriginalHorizonAfterPublicExpiry(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err != nil {
		t.Fatal(err)
	}
	f.closeHook = func(ctx context.Context) {
		d, ok := ctx.Deadline()
		if !ok || !d.Equal(f.start.Batch.Request.Call.WriteUntil) || ctx.Err() != nil {
			t.Error("cleanup lost original prepaid bound")
		}
	}
	public, cancel := context.WithCancel(context.Background())
	cancel()
	if err = r.CloseLocal(public); err != nil || f.worker.active {
		t.Fatal("canceled public request suppressed local cleanup", err)
	}
}
func TestProjectionWorkerForeignOrRepeatedKeyNeverGetsAnotherSlot(t *testing.T) {
	for _, mode := range []string{"foreign", "repeat", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionWorkerFixture(t)
			f.nativeHook = func(ctx context.Context, keys KeyOpener) error {
				if _, err := keys.Open(ctx, artifact.SealedKey{}, []byte("foreign")); err == nil || f.keyCalls != 0 {
					t.Fatal("foreign role reached key provider")
				}
				if mode == "foreign" {
					return errors.New("stop after foreign input")
				}
				aad, _ := ArtifactKeyBinding(f.source.Expectation.Binding(), "data-key")
				defer clear(aad)
				if mode == "unknown" {
					f.keyErr = errors.New("unknown key effect")
				}
				key, err := keys.Open(ctx, artifact.SealedKey{Reference: "fixture", Ciphertext: "fixture"}, aad)
				clear(key)
				if mode == "unknown" && err == nil {
					t.Fatal("unknown key result released")
				}
				if _, err = keys.Open(ctx, artifact.SealedKey{Reference: "fixture", Ciphertext: "fixture"}, aad); err == nil || f.keyCalls != 1 {
					t.Fatal("spent key retried")
				}
				for _, b := range f.lastKey {
					if b != 0 {
						t.Fatal("key retained after failed/consumed result")
					}
				}
				return errors.New("stop after repeated input")
			}
			r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
			if err == nil {
				t.Fatal("partial native read disclosed")
			}
			if r != nil {
				_ = r.CloseLocal(context.Background())
			}
		})
	}
}

func TestProjectionWorkerCloseJoinsInFlightCurrentChecks(t *testing.T) {
	f := newProjectionWorkerFixture(t)
	r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f.authorityHook = func(context.Context) { close(entered); <-release }
	checked := make(chan error, 1)
	go func() { _, err := r.Projection(context.Background()); checked <- err }()
	<-entered
	if _, err = r.Projection(context.Background()); err == nil {
		close(release)
		t.Fatal("concurrent unbounded authority check admitted")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.CloseLocal(context.Background()) }()
	select {
	case err := <-closed:
		close(release)
		t.Fatal("local close preceded blocking proof join", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err = <-checked; err == nil {
		t.Fatal("canceled proof released result")
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestProjectionWorkerShortKeyCallerAndPostKeyRevocation(t *testing.T) {
	for _, mode := range []string{"caller", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			f := newProjectionWorkerFixture(t)
			if mode == "caller" {
				f.keyHook = func(ctx context.Context) { <-ctx.Done() }
				f.nativeHook = func(ctx context.Context, keys KeyOpener) error {
					short, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
					defer cancel()
					aad, _ := ArtifactKeyBinding(f.source.Expectation.Binding(), "data-key")
					defer clear(aad)
					started := time.Now()
					key, err := keys.Open(short, artifact.SealedKey{Reference: "fixture", Ciphertext: "fixture"}, aad)
					clear(key)
					if err == nil || time.Since(started) > 300*time.Millisecond {
						t.Fatal("short key caller bound lost", err)
					}
					return errors.New("canceled key")
				}
			} else {
				f.keyHook = func(context.Context) { f.a.AccessUntil = time.Now(); f.a.ValidUntil = f.a.AccessUntil }
			}
			r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
			if err == nil || f.keyCalls != 1 {
				t.Fatal("late key result disclosed or repeated", err, f.keyCalls)
			}
			for _, b := range f.lastKey {
				if b != 0 {
					t.Fatal("late key result was retained")
				}
			}
			if r != nil {
				_ = r.CloseLocal(context.Background())
			}
		})
	}
}

func TestProjectionWorkerRejectsSourceAndWorkerReplacementBeforeKeys(t *testing.T) {
	for name, mutate := range map[string]func(*projectionWorkerFixture){
		"source-version":     func(f *projectionWorkerFixture) { f.source.Copies[0].SHA256[0]++ },
		"source-case":        func(f *projectionWorkerFixture) { f.source.Expectation.CaseID = projectionOtherID },
		"source-capture":     func(f *projectionWorkerFixture) { f.source.Expectation.CaptureUID = projectionOtherID },
		"source-pod":         func(f *projectionWorkerFixture) { f.source.Expectation.PodUID = "other-pod" },
		"source-action":      func(f *projectionWorkerFixture) { f.source.Expectation.ActionID = "other" },
		"source-limit":       func(f *projectionWorkerFixture) { f.source.Expectation.Registration.NativeLimit-- },
		"worker-process":     func(f *projectionWorkerFixture) { f.proof.ProcessEpoch = projectionOtherID },
		"worker-certificate": func(f *projectionWorkerFixture) { f.proof.Peer.Certificate[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			f := newProjectionWorkerFixture(t)
			mutate(f)
			r, err := f.worker.ExecuteProjection(context.Background(), f.start, f)
			if err == nil || f.reads != 0 || f.keyCalls != 0 {
				t.Fatal("replacement reached native/key work", err)
			}
			if r != nil {
				_ = r.CloseLocal(context.Background())
			}
		})
	}
}
