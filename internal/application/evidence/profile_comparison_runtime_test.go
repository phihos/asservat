package evidence

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// These ports isolate the real ProjectionRuntime orchestration. Source facts,
// SQL claims/key effects, Pod proof, transport and result are synthetic; this
// does not qualify any of those authorities or perform actual unwraps.
type comparisonRuntimePorts struct {
	t                             *testing.T
	q                             query.ContextQuery
	a                             query.ContextProjectionAuthority
	start                         query.ContextReadStart
	credential                    ProjectionCredential
	sources                       [2]NativeContextSource
	registration                  NativeExchangeRegistration
	before                        func(context.Context, NativeOrigin) error
	check                         func(context.Context, NativeOrigin) (value.NativeLease, error)
	origin                        NativeOrigin
	operation                     value.NativeOperation
	events                        []string
	keys                          [2]string
	bound                         time.Time
	closed, claimed, acknowledged bool
	wrongObservedBaseline         bool
}

func comparisonRuntimeFixture(t *testing.T) (*ProjectionRuntime, *comparisonRuntimePorts) {
	t.Helper()
	f := newProjectionWorkerFixture(t)
	source := cloneNativeSource(f.source)
	e := &source.Expectation
	e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "go", EndpointDigest: artifact.Digest{1}, Type: "cpu", Mode: "interval", DurationMillis: 1000}
	e.Registration.NativeLimit = artifact.MaxPprofBytes
	a := f.a
	a.Scope.NativeType, a.Scope.SourceFormat, a.Scope.DisplayVersion = artifact.PprofArtifact, artifact.PprofFormat, query.ProfileSummaryDisplayVersion
	a.Scope.SourceProjectionDigest, a.Scope.Selection, a.Scope.Profile = artifact.Digest{}, query.LineSelection{}, query.ProfileSummarySelection{SampleType: "cpu", TopN: 20}
	baseline := a
	baseline.Scope.CaseID, baseline.Scope.ArtifactID, baseline.Scope.CaptureID = projectionOtherID, projectionOtherID, projectionOtherID
	baseline.Environment.Location.ArtifactID = projectionOtherID
	baseline.Environment.Processing.Location = baseline.Environment.Location
	baseline.Environment.Processing.CaptureID = projectionOtherID
	baseline.Environment.Path.ID = projectionOtherID // distinct accepted route, same physical reader
	bs := cloneNativeSource(source)
	bs.Expectation.CaseID, bs.Expectation.CaptureUID = projectionOtherID, projectionOtherID
	bs.Expectation.Registration.Location.ArtifactID = projectionOtherID
	a.Scope.DisplayVersion = query.ProfileComparisonDisplayVersion
	a.Scope.Comparison = query.ProfileComparisonWindow{Normalization: query.ProfileComparisonRaw, Baseline: query.ProfileComparisonBaseline{CaseID: baseline.Scope.CaseID, ArtifactID: baseline.Scope.ArtifactID, CaptureID: baseline.Scope.CaptureID, ClusterID: baseline.Scope.ClusterID, NamespaceUID: baseline.Scope.NamespaceUID, WorkloadUID: baseline.Scope.WorkloadUID, PodUID: baseline.Scope.PodUID, Version: baseline.Scope.Version}}
	a.Baseline = &baseline
	plan := f.p
	plan.Profile.Worker.MemoryBytes = query.ProfileComparisonWorkerBytes
	plan.Profile.Worker.WorkerTransientBytes = query.ProfileComparisonWorkerBytes
	baselinePlan := plan
	baselinePlan.Profile.Path = baseline.Environment.Path
	q, err := query.NewProfileComparisonQuery(f.q.ID, f.q.OperationID, f.q.WorkerID, a, baselinePlan, plan, f.now)
	if err != nil {
		t.Fatal("paired query fixture", err)
	}
	original := routeTestWorker(t, 1)
	profile := original.Intent.Profile
	profile.InstallationID, profile.ClusterID, profile.Configuration = q.Plan.InstallationID, q.Plan.Profile.Path.AcquisitionClusterID, q.Plan.Profile.Path.WorkerConfiguration
	profile.MemoryBytes = query.ProfileComparisonWorkerBytes
	intent := value.AcquisitionWorkerIntent{ID: q.WorkerID, Parent: value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}, Profile: profile, CreatedAt: q.CreatedAt, RunUntil: q.WorkerUntil}
	binding := original.Binding.Acquisition()
	binding.Parent = intent.Parent
	binding.InstallationID = profile.InstallationID
	binding.ClusterID = profile.ClusterID
	binding.Job = intent.JobName()
	worker := value.AcquisitionWorker{Intent: intent, Binding: binding, Job: value.DownloadWorkerJob{IntentID: intent.ID, UID: binding.JobUID, Spec: binding.JobSpec}}
	enrollment := value.AcquisitionEnrollment{Worker: worker, PublicKeyDigest: artifact.Digest{3}, ClaimedAt: f.now}
	peer := value.KeyPeer{InstallationID: profile.InstallationID, PeerID: binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{4}, NotBefore: f.now.Add(-time.Second), NotAfter: q.CredentialUntil}
	start := f.start
	start.Batch.Worker = query.ContextQueryWorker{QueryID: q.ID, WorkerID: q.WorkerID, PeerID: peer.PeerID, PodUID: binding.PodUID, ProcessEpoch: q.WorkerID, Certificate: peer.Certificate, Configuration: profile.Configuration}
	start.Batch.Request.Call.Tool = "compare_profiles"
	start.Batch.CleanupUntil = q.CleanupUntil
	p := &comparisonRuntimePorts{t: t, q: q, a: a, start: start, credential: ProjectionCredential{Enrollment: enrollment, Peer: peer, Ready: true}, sources: [2]NativeContextSource{bs, source}, bound: a.ValidUntil}
	if !enrollment.Valid() || !start.Batch.Current(q, a, time.Now()) || !ProjectionComparisonSourcesMatch(p.sources, q.Scope, a) {
		t.Fatal("invalid composed paired source/identity fixture", enrollment.Valid(), e.Validate(), bs.Expectation.Validate())
	}
	runtime := &ProjectionRuntime{Sources: p, Identities: p, Operations: p, Registrar: p, KeyScope: value.KeyScope{InstallationID: profile.InstallationID, Purpose: "artifact", KeyID: "synthetic"}, HubPodUID: projectionID, HubProcessEpoch: start.Batch.Request.HubProcessEpoch, Now: time.Now}
	runtime.Origins = NativeOrigins{Projection: p, Now: time.Now}
	return runtime, p
}

func (p *comparisonRuntimePorts) step(ctx context.Context, name string) error {
	p.events = append(p.events, name)
	if d, ok := ctx.Deadline(); !ok || d.After(p.bound) {
		return errors.New("operation renewed original bound")
	}
	return ctx.Err()
}
func (p *comparisonRuntimePorts) Request() query.ContextQueryRequest { return p.start.Batch.Request }
func (p *comparisonRuntimePorts) CheckCurrent(ctx context.Context) (query.ContextProjectionAuthority, error) {
	return ownedProjectionAuthority(p.a), ctx.Err()
}
func (p *comparisonRuntimePorts) ReadProjectionCredential(ctx context.Context, q query.ContextQuery, _ query.ContextQueryRequest, a query.ContextProjectionAuthority) (ProjectionCredential, error) {
	if !q.Equal(p.q) || !sameProjectionAuthority(a, p.a) {
		return ProjectionCredential{}, query.ErrUnavailable
	}
	return p.credential, p.step(ctx, "credential")
}
func (p *comparisonRuntimePorts) BindProjectionIdentity(context.Context, query.ContextQuery, query.ContextQueryRequest, query.ContextProjectionAuthority, ProjectionCredential) (query.ContextQueryWorker, error) {
	return query.ContextQueryWorker{}, query.ErrUnavailable
}
func (p *comparisonRuntimePorts) ReadProjectionSource(context.Context, query.ContextQuery, query.ContextProjectionAuthority, query.ContextQueryRequest) (NativeContextSource, error) {
	if p.q.Scope.Comparison != (query.ProfileComparisonWindow{}) {
		p.t.Error("pair used scalar source port")
		return NativeContextSource{}, query.ErrUnavailable
	}
	return cloneNativeSource(p.sources[1]), nil
}
func (p *comparisonRuntimePorts) ReadProjectionComparisonSources(ctx context.Context, q query.ContextQuery, a query.ContextProjectionAuthority, _ query.ContextQueryRequest) ([2]NativeContextSource, error) {
	if !q.Equal(p.q) || !sameProjectionAuthority(a, p.a) {
		return [2]NativeContextSource{}, query.ErrUnavailable
	}
	return p.sources, p.step(ctx, "sources")
}
func (p *comparisonRuntimePorts) RegisterNativeExchange(ctx context.Context, r NativeExchangeRegistration, before func(context.Context, NativeOrigin) error, check func(context.Context, NativeOrigin) (value.NativeLease, error)) (NativePendingExchange, error) {
	if r.Projection == nil {
		return nil, query.ErrUnavailable
	}
	if p.q.Scope.Comparison == (query.ProfileComparisonWindow{}) {
		if r.BaselineSource != nil || *r.Projection != p.q.Scope || !reflect.DeepEqual(r.Source, p.sources[1]) {
			return nil, query.ErrUnavailable
		}
	} else if r.BaselineSource == nil || !NativeComparisonSourcesMatch([2]NativeContextSource{*r.BaselineSource, r.Source}, *r.Projection, r.Operation) || !reflect.DeepEqual([2]NativeContextSource{*r.BaselineSource, r.Source}, p.sources) {
		return nil, query.ErrUnavailable
	}
	p.registration, p.before, p.check = r, before, check
	return comparisonRuntimePending{p}, p.step(ctx, "register")
}
func (p *comparisonRuntimePorts) ClaimProjectionNative(ctx context.Context, start query.ContextReadStart, a query.ContextProjectionAuthority, o value.NativeOperation) error {
	if !start.Batch.Equal(p.start.Batch) || start.ClaimID != p.start.Batch.ID || !start.Fresh || !sameProjectionAuthority(a, p.a) || !o.Equal(p.registration.Operation) {
		return query.ErrUnavailable
	}
	p.claimed = true
	p.operation = o
	return p.step(ctx, "claim-native")
}
func (p *comparisonRuntimePorts) ObserveProjectionNativeOperation(ctx context.Context, ref value.NativeReference, peer value.KeyPeer) (value.NativeLease, error) {
	if !p.claimed || ref != p.operation.Reference || peer != p.credential.Peer {
		return value.NativeLease{}, query.ErrUnavailable
	}
	lease := value.NativeLease{Operation: p.operation, Certificate: peer.Certificate, Sequence: 1, ObservedAt: p.operation.StartedAt, Until: p.operation.Until}
	if p.wrongObservedBaseline {
		lease.Operation.Baseline.SourceVersion[0]++
	}
	return lease, p.step(ctx, "observe-native")
}
func (p *comparisonRuntimePorts) BindProjectionNativeKeys(ctx context.Context, start query.ContextReadStart, a query.ContextProjectionAuthority, o value.NativeOperation, _ value.KeyScope, origin NativeOrigin) error {
	if !p.claimed || !start.Batch.Equal(p.start.Batch) || !sameProjectionAuthority(a, p.a) || !o.Equal(p.operation) || !origin.Lease.Operation.Equal(o) || !origin.Proof.Valid(time.Now()) {
		return query.ErrUnavailable
	}
	var err error
	if p.q.Scope.Comparison == (query.ProfileComparisonWindow{}) {
		p.keys[0] = start.Batch.ID
	} else {
		p.keys, err = query.ProfileComparisonKeyChildIDs(start.Batch.ID)
	}
	if err != nil {
		return err
	}
	return p.step(ctx, "bind-two-key-children")
}
func (p *comparisonRuntimePorts) CompleteProjectionNative(ctx context.Context, l value.NativeLease) error {
	if !l.Operation.Equal(p.operation) || l.Certificate != p.credential.Peer.Certificate {
		return query.ErrUnavailable
	}
	return p.step(ctx, "complete-native")
}
func (p *comparisonRuntimePorts) ReadAcquisitionEnrollment(context.Context, value.AcquisitionParent, string) (value.AcquisitionWorkerIdentity, error) {
	return value.AcquisitionWorkerIdentity{}, query.ErrUnavailable
}
func (p *comparisonRuntimePorts) ReadProjectionWorkerCertificate(context.Context, string, string, []byte) (value.WorkerCertificate, error) {
	return value.WorkerCertificate{}, query.ErrUnavailable
}
func (p *comparisonRuntimePorts) LocateProjectionNativeOperation(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error) {
	return value.NativeLease{}, query.ErrUnavailable
}

type comparisonRuntimePending struct{ p *comparisonRuntimePorts }

func (p comparisonRuntimePending) Wait(ctx context.Context) (NativeExchange, error) {
	f := p.p
	if !f.claimed {
		return nil, query.ErrUnavailable
	}
	f.origin = NativeOrigin{Lease: value.NativeLease{Operation: f.operation, Certificate: f.credential.Peer.Certificate, Sequence: 1, ObservedAt: f.operation.StartedAt, Until: f.operation.Until}, Proof: value.AcquisitionPeerProof{Binding: f.credential.Enrollment.Worker.Binding, Peer: f.credential.Peer, TokenDigest: artifact.Digest{1}, ObservedAt: f.operation.StartedAt, FreshUntil: f.operation.Until}}
	if _, err := f.check(ctx, f.origin); err != nil {
		return nil, err
	}
	if err := f.before(ctx, f.origin); err != nil {
		return nil, err
	}
	if _, err := f.check(ctx, f.origin); err != nil {
		return nil, err
	}
	return comparisonRuntimeExchange{f}, f.step(ctx, "wait-connected")
}
func (p comparisonRuntimePending) Close() {
	p.p.closed = true
	p.p.events = append(p.p.events, "close")
}

type comparisonRuntimeExchange struct{ p *comparisonRuntimePorts }

func (e comparisonRuntimeExchange) Projection(ctx context.Context) (query.ProjectionResult, error) {
	if _, err := e.p.check(ctx, e.p.origin); err != nil {
		return query.ProjectionResult{}, err
	}
	if e.p.q.Scope.Comparison == (query.ProfileComparisonWindow{}) {
		return query.ProjectionResult{Summary: &query.ProfileSummary{SampleType: "cpu", Unit: "nanoseconds", SymbolStatus: "missing", Top: []query.ProfileHotspot{}}}, e.p.step(ctx, "read-result")
	}
	return query.ProjectionResult{IncompatibleProfiles: true}, e.p.step(ctx, "read-result")
}
func (e comparisonRuntimeExchange) AcknowledgeProjection(ctx context.Context) error {
	if err := e.p.registration.Complete(ctx, e.p.origin.Lease); err != nil {
		return err
	}
	e.p.acknowledged = true
	return e.p.step(ctx, "ack-result")
}
func (comparisonRuntimeExchange) Commit(context.Context) error { return query.ErrUnavailable }
func (comparisonRuntimeExchange) Close() error                 { return nil }
func (comparisonRuntimeExchange) Prepared(context.Context) (artifact.NativeDownloadMetadata, error) {
	return artifact.NativeDownloadMetadata{}, query.ErrUnavailable
}
func (comparisonRuntimeExchange) ReadChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) (NativeResponseChunk, error) {
	return NativeResponseChunk{}, query.ErrUnavailable
}
func (comparisonRuntimeExchange) AcknowledgeNativeChunk(context.Context, artifact.DownloadDeliveryLease, int64, int64) error {
	return query.ErrUnavailable
}

func TestComparisonRuntimeComposesPairClaimKeysCurrentResultAndClosure(t *testing.T) {
	for _, mode := range []string{"complete", "short-caller", "scalar-short-caller", "changed-observed-baseline", "foreign-claim", "replayed-claim"} {
		t.Run(mode, func(t *testing.T) {
			runtime, p := comparisonRuntimeFixture(t)
			scalar := mode == "scalar-short-caller"
			if scalar {
				p.q.Scope, _ = p.q.Scope.IncidentScope()
				p.q.BaselinePlan = query.ContextQueryPlan{}
				p.a.Scope = p.q.Scope
				p.a.Baseline = nil
				p.start.Batch.Request.Call.Tool = "get_profile_summary"
			}
			if mode == "changed-observed-baseline" {
				p.wrongObservedBaseline = true
			}
			if mode == "short-caller" || scalar {
				p.bound = p.bound.Add(-time.Second)
			}
			ctx, cancel := context.WithDeadline(t.Context(), p.bound)
			defer cancel()
			start := p.start
			if mode == "foreign-claim" {
				start.ClaimID = projectionOtherID
			}
			if mode == "replayed-claim" {
				start.Fresh = false
			}
			read, err := runtime.ReadProjection(ctx, p.q, start, p)
			if mode == "foreign-claim" || mode == "replayed-claim" {
				if err == nil || read != nil || len(p.events) != 0 || p.claimed {
					t.Fatal("invalid read-batch claim reached effects", err, p.events)
				}
				return
			}
			if mode == "changed-observed-baseline" {
				if err == nil || read != nil || p.keys != ([2]string{}) || !p.closed {
					t.Fatal("changed baseline reached keys/result", err, p.events)
				}
				return
			}
			if err != nil || read == nil {
				t.Fatal("paired runtime failed", err, p.events)
			}
			t.Cleanup(func() { _ = read.Close(context.Background()) })
			if p.operation.Until.After(p.bound) {
				t.Fatal("serialized native operation renewed caller cutoff", p.operation.Until, p.bound, p.events)
			}
			result, err := read.Projection(ctx)
			if err != nil || result.IncompatibleProfiles == scalar || !result.Valid(p.q.Scope) || !p.acknowledged || p.keys[0] == "" || (!scalar && p.keys[0] == p.keys[1]) || (scalar && (p.keys[0] != p.start.Batch.ID || p.keys[1] != "")) {
				t.Fatal("paired handoff changed authority or lost key children", err, p.events)
			}
			if err := read.Close(ctx); err != nil {
				t.Fatal(err)
			}
			joined := false
			if err := read.WithProjectionClosed(ctx, p.start.Batch, func(context.Context) error { joined = true; return nil }); err != nil || !joined || !p.closed {
				t.Fatal("positive closure lost", err, p.events)
			}
		})
	}
}
