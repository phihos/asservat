package native_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	native "asservat.local/asservat/internal/transport/native"
)

// projectionStoredOperations answers as the SQL projection observation does:
// the stored operation with its own original interval.
type projectionStoredOperations struct {
	lease           value.NativeLease
	calls, revokeAt *atomic.Int32
}

func (p projectionStoredOperations) LocateProjectionNativeOperation(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error) {
	return p.lease, nil
}
func (p projectionStoredOperations) ReadAcquisitionEnrollment(context.Context, value.AcquisitionParent, string) (value.AcquisitionWorkerIdentity, error) {
	return value.AcquisitionWorkerIdentity{}, contracts.ErrNativeProtocol
}
func (p projectionStoredOperations) ReadProjectionWorkerCertificate(context.Context, string, string, []byte) (value.WorkerCertificate, error) {
	return value.WorkerCertificate{}, contracts.ErrNativeProtocol
}
func (p projectionStoredOperations) ObserveProjectionNativeOperation(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error) {
	if n := p.calls.Add(1); p.revokeAt.Load() > 0 && n >= p.revokeAt.Load() {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable // e.g. SQL suspension
	}
	return p.lease, nil
}

// projectionWorkerPeers mirrors NativePeerChecks for a projection worker: the
// admission origin and every recheck end with the worker's five-second
// enrollment observation, while the operation and Pod proof span 20 s.
type projectionWorkerPeers struct {
	origin  evidence.NativeOrigin
	origins *evidence.NativeOrigins
	hello   contracts.NativeHello
}

func (p *projectionWorkerPeers) CheckWorkerNative(_ context.Context, _ *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	if h.Reference != p.hello.Reference {
		return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
	}
	return p.origin, nil
}
func (p *projectionWorkerPeers) CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
}
func (p *projectionWorkerPeers) RecheckWorkerNative(ctx context.Context, _ *tls.ConnectionState, origin evidence.NativeOrigin) (value.NativeLease, error) {
	l, e := p.origins.Recheck(ctx, origin)
	if e != nil {
		return l, e
	}
	l.Until = identity.Earlier(l.Until, time.Now().Add(5*time.Second))
	return l, nil
}
func (p *projectionWorkerPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return value.NativeLease{}, contracts.ErrNativeProtocol
}

// Installed native82: a projection worker attached to its published 20 s
// operation, but the hub refused it at admission/gate. The worker admission,
// router, registration and both frame gates are the production code; the
// worker/SQL observations are synthetic with installed-like intervals.
func TestHubWorkerAdmissionAttachesTwentySecondProjection(t *testing.T) {
	for _, lifetime := range []time.Duration{4 * time.Second, identity.EvidenceReadRequestWindow} {
		t.Run(lifetime.String(), func(t *testing.T) { testHubWorkerProjectionLifetime(t, lifetime, 0) })
	}
	// A revoked operation observation at the worker gate's own recheck refuses
	// the worker and names the inner stage for the operator report.
	t.Run("revoked-at-gate", func(t *testing.T) { testHubWorkerProjectionLifetime(t, identity.EvidenceReadRequestWindow, 5) })
}
func testHubWorkerProjectionLifetime(t *testing.T, lifetime time.Duration, revokeAt int32) {
	f := newProjectionProtocolFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := f.lease.Operation
	op.StartedAt, op.Until = now, now.Add(lifetime)
	op.Processing.ObservedAt, op.Processing.ValidUntil = now, op.Until
	stored := value.NativeLease{Operation: op, Certificate: f.lease.Certificate, Sequence: 1, ObservedAt: op.StartedAt, Until: op.Until}
	peer := value.KeyPeer{InstallationID: nativeID, PeerID: nativeID, Role: "acquisition", Certificate: stored.Certificate, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	binding := value.AcquisitionWorkerBinding{Parent: value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: op.Reference.QueryID}, InstallationID: nativeID, ClusterID: nativeID, Namespace: "private-workers", NamespaceUID: nativeID, ServiceAccount: "acquisition", ServiceAccountUID: nativeID, Job: "query", JobUID: nativeID, Pod: "query-pod", PodUID: nativeID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}}
	proof := value.AcquisitionPeerProof{Binding: binding, Peer: peer, TokenDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(identity.EvidenceReadRequestWindow)}
	origin := evidence.NativeOrigin{Lease: stored, Proof: proof}
	origin.Lease.Until = identity.Earlier(op.Until, now.Add(5*time.Second)) // CheckWorkerNative: enrollment observation
	if !origin.Lease.Valid(now) || !proof.Valid(now) || !op.CurrentValid(now) {
		t.Fatal("invalid installed-like projection fixture")
	}
	stored0 := projectionStoredOperations{lease: stored, calls: new(atomic.Int32), revokeAt: new(atomic.Int32)}
	stored0.revokeAt.Store(revokeAt)
	// No shared recent observation: every recheck reads the operation.
	origins := &evidence.NativeOrigins{Projection: stored0, Now: time.Now}
	if _, e := origins.Recheck(f.ctx, origin); e != nil {
		t.Fatal("recheck", e)
	}
	router, err := native.NewHubRouter(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	pending, err := router.RegisterNativeExchange(ctx, evidence.NativeExchangeRegistration{Operation: op, Projection: &f.scope, Source: f.source, Complete: syntheticNativeCompletion},
		func(context.Context, evidence.NativeOrigin) error { return nil },
		func(bound context.Context, o evidence.NativeOrigin) (value.NativeLease, error) {
			return origins.Recheck(bound, o)
		})
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	peers := &projectionWorkerPeers{origin: origin, origins: origins, hello: f.hello}
	serving := &hubWorkerServing{until: now.Add(5 * time.Second), pod: nativeID}
	a, err := native.NewHubWorkerAdmission(peers, serving, router, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := a.OpenNative(ctx, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}, f.hello)
	if revokeAt > 0 {
		var s interface{ FixedStep() string }
		if conversation != nil || !errors.Is(err, artifact.ErrDownloadUnavailable) || !errors.As(err, &s) || s.FixedStep() != "gate/check/worker/observe" {
			step := ""
			if s != nil {
				step = s.FixedStep()
			}
			t.Fatal("revoked operation not refused with its inner stage", err, step)
		}
		return
	}
	if err != nil || conversation == nil {
		var s interface{ FixedStep() string }
		step := ""
		if errors.As(err, &s) {
			step = s.FixedStep()
		}
		t.Fatal("projection worker refused at", step, err)
	}
	defer conversation.Close()
	lease, err := conversation.Gate().Check(ctx)
	if err != nil || lifetime > 5*time.Second && !lease.Until.After(now.Add(5*time.Second)) {
		t.Fatal("worker gate did not span the projection operation", err, lease.Until.Sub(now))
	}
}

// Installed native88: the worker read and returned the projection, the hub's
// operation closed its SQL native row, and the hub then refused its own final
// close (serve/close): the operation's completion proof names its inner gate,
// while a hub-local worker conversation streams under the outer peer gate.
// Production worker admission, router, registration, both gates, handler and
// real TLS/h2 run the complete approved exchange to the joined close.
func TestHubWorkerProjectionConversationJoinsThroughPeerGate(t *testing.T) {
	f := newProjectionProtocolFixture(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	op := f.lease.Operation
	op.StartedAt, op.Until = now, now.Add(identity.EvidenceReadRequestWindow)
	op.Processing.ObservedAt, op.Processing.ValidUntil = now, op.Until
	stored := value.NativeLease{Operation: op, Certificate: f.lease.Certificate, Sequence: 1, ObservedAt: op.StartedAt, Until: op.Until}
	f.lease = stored
	peer := value.KeyPeer{InstallationID: nativeID, PeerID: nativeID, Role: "acquisition", Certificate: stored.Certificate, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute)}
	binding := value.AcquisitionWorkerBinding{Parent: value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: op.Reference.QueryID}, InstallationID: nativeID, ClusterID: nativeID, Namespace: "private-workers", NamespaceUID: nativeID, ServiceAccount: "acquisition", ServiceAccountUID: nativeID, Job: "query", JobUID: nativeID, Pod: "query-pod", PodUID: nativeID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}}
	origin := evidence.NativeOrigin{Lease: stored, Proof: value.AcquisitionPeerProof{Binding: binding, Peer: peer, TokenDigest: artifact.Digest{4}, ObservedAt: now, FreshUntil: now.Add(identity.EvidenceReadRequestWindow)}}
	origin.Lease.Until = now.Add(5 * time.Second)
	stored0 := projectionStoredOperations{lease: stored, calls: new(atomic.Int32), revokeAt: new(atomic.Int32)}
	origins := &evidence.NativeOrigins{Projection: stored0, Now: time.Now}
	router, err := native.NewHubRouter(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	var completed atomic.Int32
	pending, err := router.RegisterNativeExchange(f.ctx, evidence.NativeExchangeRegistration{Operation: op, Projection: &f.scope, Source: f.source, Complete: func(ctx context.Context, l value.NativeLease) error {
		completed.Add(1)
		return ctx.Err()
	}}, func(context.Context, evidence.NativeOrigin) error { return nil },
		func(bound context.Context, o evidence.NativeOrigin) (value.NativeLease, error) {
			return origins.Recheck(bound, o)
		})
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	peers := &projectionWorkerPeers{origin: origin, origins: origins, hello: f.hello}
	a, err := native.NewHubWorkerAdmission(peers, &hubWorkerServing{until: now.Add(5 * time.Second), pod: nativeID}, router, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var hubStep atomic.Value
	client := flowServerReporting(t, contracts.NativeWorkerPath, a, func(_ context.Context, stage string, err error) {
		var s interface{ FixedStep() string }
		if errors.As(err, &s) {
			stage += "/" + s.FixedStep()
		}
		hubStep.Store(stage)
	})
	// The fixture's frame-inspecting stream pins its own command interval;
	// this test runs the actual worker conversation on the plain stream.
	stream, err := client.Open(f.ctx, f.hello)
	if err != nil {
		t.Fatal(err)
	}
	result := f.result(t, f.reader())
	done := make(chan projectionProtocolOutcome, 1)
	go func() {
		defer stream.Close()
		state, err := native.RunWorkerConversation(f.ctx, stream, f.hello, f.target, artifact.Digest{1}, result)
		done <- projectionProtocolOutcome{state, err}
	}()
	exchange, err := pending.Wait(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	projection, ok := exchange.(evidence.NativeProjectionExchange)
	if !ok {
		t.Fatal("not a projection exchange")
	}
	if _, err = projection.Projection(f.ctx); err != nil {
		out := projectionProtocolReceive(t, f.ctx, done)
		var s interface{ FixedStep() string }
		step := ""
		if errors.As(out.err, &s) {
			step = s.FixedStep()
		}
		t.Fatal("projection not received", err, out.err, step, hubStep.Load())
	}
	if err = projection.AcknowledgeProjection(f.ctx); err != nil {
		t.Fatal("hub refused its own final close", err, hubStep.Load())
	}
	if out := projectionProtocolReceive(t, f.ctx, done); out.err != nil || out.state.State != contracts.NativeJoined || completed.Load() != 1 {
		t.Fatal("hub-local projection conversation did not join", out.err, completed.Load())
	}
}
