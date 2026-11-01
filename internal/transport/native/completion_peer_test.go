package native_test

import (
	"context"
	"crypto/tls"
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

type completionHubPeers struct {
	origin  evidence.NativeOrigin
	current func() value.NativeLease
}

func (p completionHubPeers) CheckForwardedNative(_ context.Context, s *tls.ConnectionState, _ contracts.NativeHello) (evidence.NativeOrigin, error) {
	if s == nil || !s.HandshakeComplete || len(s.VerifiedChains) == 0 {
		return evidence.NativeOrigin{}, artifact.ErrDownloadUnavailable
	}
	return p.origin, nil
}
func (p completionHubPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return p.current(), nil
}
func (p completionHubPeers) CheckWorkerNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, artifact.ErrInvalid
}
func (p completionHubPeers) RecheckWorkerNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return value.NativeLease{}, artifact.ErrInvalid
}

type completionHubServing struct{ until time.Time }

func (s completionHubServing) CheckOwnerServing(context.Context) (time.Time, error) {
	return s.until, nil
}
func (s completionHubServing) CheckNativeHub(context.Context, value.NativeOperation) (time.Time, error) {
	return s.until, nil
}

// Actual HubAdmission (including its separate peer gate), router, operation,
// worker and two-hop mTLS/H2. SQL, peer/source authority and bytes are synthetic.
// A short retained peer observation is still valid when the inner SQL lease
// advances. The exact positive close must not mistake that for another owner.
func TestNativeHubCompletionWithRetainedPeerObservation(t *testing.T) {
	for _, mode := range []string{"outer-before-proof", "outer-after-proof"} {
		t.Run(mode, func(t *testing.T) { testNativeHubCompletionPeer(t, mode) })
	}
}
func testNativeHubCompletionPeer(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	source := flowSourceValue(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &flowSource{}
	result, err := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()
	prep, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	metadata, err := prep.Prepared(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = prep.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	prep.Close()
	now = time.Now()
	authority := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
	delivery := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Length: metadata.Size, StartedAt: now, Until: authority.ValidUntil, Authority: authority}
	origin, _, _ := routerFixture(t)
	origin.Lease.Operation.Kind = value.NativeResponse
	origin.Lease.Operation.Reference.Fence = 2
	origin.Lease.Operation.Until = now.Add(7 * time.Second)
	origin.Lease.ObservedAt = now
	origin.Lease.Until = delivery.Until
	var sequence atomic.Int64
	sequence.Store(1)
	var closed atomic.Bool
	var closeCalls atomic.Int32
	current := func() value.NativeLease { l := origin.Lease; l.Sequence = sequence.Load(); return l }
	router, err := native.NewHubRouter(1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	pending, err := router.RegisterNativeExchange(ctx, evidence.NativeExchangeRegistration{Operation: origin.Lease.Operation, Source: source, Delivery: delivery, Complete: func(call context.Context, l value.NativeLease) error {
		closeCalls.Add(1)
		if call.Err() != nil || l.Sequence != 2 || !l.Operation.Equal(origin.Lease.Operation) {
			return artifact.ErrDownloadUnavailable
		}
		closed.Store(true)
		return nil
	}}, func(context.Context, evidence.NativeOrigin) error { return nil }, func(context.Context, evidence.NativeOrigin) (value.NativeLease, error) {
		if closed.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		return current(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	hub, err := native.NewHubAdmission(completionHubPeers{origin, func() value.NativeLease {
		l := current()
		if mode == "outer-before-proof" {
			l.Until = now.Add(3 * time.Second)
		}
		return l
	}}, completionHubServing{origin.Lease.Operation.Until}, router, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	upstream := flowServerReporting(t, contracts.NativeOwnerPath, hub, func(_ context.Context, stage string, err error) {
		if e, ok := err.(interface{ FixedStep() string }); ok {
			t.Log("hub refusal", stage, e.FixedStep())
		} else {
			t.Log("hub refusal", stage, err)
		}
	})
	connector := &flowAdmission{t: t, owner: ctx, lease: origin.Lease, upstream: upstream, check: func(context.Context) (value.NativeLease, error) { return current(), nil }}
	client = flowServer(t, contracts.NativeWorkerPath, connector)
	stream, e := client.Open(ctx, workerHello())
	if e != nil {
		t.Fatal(e)
	}
	commandSeen := make(chan struct{})
	workerDone := make(chan error, 1)
	done = workerDone
	go func() {
		workerDone <- native.RunWorker(ctx, completionCommandStream{stream, commandSeen}, workerHello(), target, artifact.Digest{1}, result)
	}()
	exchange, err := pending.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-commandSeen:
	case e := <-done:
		t.Fatal("worker stopped before command", e)
	case <-ctx.Done():
		t.Fatal("command not received", ctx.Err())
	}
	sequence.Store(2)
	delivery.Sequence = 2
	chunk, err := exchange.ReadChunk(ctx, delivery, 0, metadata.Size)
	if err != nil {
		workerErr := <-done
		if e, ok := workerErr.(interface{ FixedStep() string }); ok {
			t.Fatal(err, "worker", e.FixedStep())
		}
		t.Fatal(err, "worker", workerErr)
	}
	if string(chunk.Bytes) != string(flowBody) {
		t.Fatal("changed response")
	}
	clear(chunk.Bytes)
	err = exchange.AcknowledgeNativeChunk(ctx, delivery, 0, metadata.Size)
	workerErr := <-done
	if err != nil || workerErr != nil || !closed.Load() || closeCalls.Load() != 1 {
		t.Fatalf("exact acknowledged close did not finish: ack=%v worker=%v closed=%v calls=%d", err, workerErr, closed.Load(), closeCalls.Load())
	}
	if reader.reads.Load() != 2 {
		t.Fatal("expected preparation plus one response source read", reader.reads.Load())
	}
}

type completionCommandStream struct {
	native.Stream
	seen chan struct{}
}

func (s completionCommandStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, e := s.Stream.Receive(ctx)
	if e == nil && f.Kind == contracts.NativeCommandFrame {
		close(s.seen)
	}
	return f, e
}
