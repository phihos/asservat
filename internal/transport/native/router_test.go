package native_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

func routerFixture(t *testing.T) (evidence.NativeOrigin, contracts.NativeHello, native.NativeOperationFactory) {
	t.Helper()
	source := flowSourceValue(t)
	n := time.Now()
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: 1}, Kind: value.NativePrepare, HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: evidence.ContextCopiesDigest(source.Copies), ParentID: nativeID, Generation: 1, StartedAt: n, Until: n.Add(4 * time.Second)}
	o = syntheticProcessingPath(o)
	o.Processing.Location = source.Expectation.Registration.Location
	o.Path.TargetClusterID = o.Processing.Location.ClusterID
	o.Path.StoreID = source.Expectation.Registration.StoreID
	peer := value.KeyPeer{InstallationID: nativeID, PeerID: nativeID, Role: "acquisition", Certificate: artifact.Digest{3}, NotBefore: n.Add(-time.Minute), NotAfter: n.Add(time.Minute)}
	binding := value.KeyWorkerBinding{InstallationID: nativeID, DownloadID: nativeID, ClusterID: nativeID, Namespace: "private-workers", NamespaceUID: nativeID, ServiceAccount: "acquisition", ServiceAccountUID: nativeID, Job: "download", JobUID: nativeID, Pod: "download-pod", PodUID: nativeID, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}}
	origin := evidence.NativeOrigin{Lease: value.NativeLease{Operation: o, Certificate: peer.Certificate, Sequence: 1, ObservedAt: n, Until: o.Until}, Proof: (value.KeyWorkerProof{Binding: binding, Peer: peer, TokenDigest: artifact.Digest{4}, ObservedAt: n, FreshUntil: o.Until}).Acquisition()}
	h := workerHello()
	h.Reference.OperationID = nativeID
	h.Reference.Fence = 1
	factory := func(owner, call context.Context, got evidence.NativeOrigin, _ contracts.NativeHello) (*native.HubOperation, error) {
		if !got.Lease.Operation.Equal(o) {
			return nil, artifact.ErrDownloadUnavailable
		}
		gate, e := evidence.NewNativeFrameGate(owner, func(context.Context) (value.NativeLease, error) { return origin.Lease, nil }, time.Now)
		if e != nil {
			return nil, e
		}
		operation, _ := json.Marshal(o)
		encoded, _ := json.Marshal(source)
		command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: h.Reference, Kind: string(o.Kind), Source: encoded, Operation: operation, ParentID: o.ParentID, Generation: o.Generation, LeaseSequence: 1, Until: o.Until.UTC().Format(time.RFC3339Nano)}
		result, e := native.NewHubOperation(gate, command, source, syntheticNativeCompletion)
		if e != nil {
			gate.Close()
			_ = gate.Wait(context.Background())
		}
		return result, e
	}
	if !origin.Lease.Valid(n) || !origin.Proof.Valid(n) {
		t.Fatal("invalid explicit synthetic router authority")
	}
	return origin, h, factory
}

func TestNativeRouterExactOwnerAndSingleAttachment(t *testing.T) {
	origin, h, factory := routerFixture(t)
	router, e := native.NewHubRouter(1)
	if e != nil {
		t.Fatal(e)
	}
	defer router.Close()
	registration, e := router.Register(context.Background(), origin.Lease.Operation, factory)
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*evidence.NativeOrigin, *contracts.NativeHello){
		func(o *evidence.NativeOrigin, h *contracts.NativeHello) {
			o.Lease.Operation.HubProcessEpoch = "22222222-2222-4222-8222-222222222222"
		},
		func(o *evidence.NativeOrigin, h *contracts.NativeHello) {
			o.Lease.Operation.Reference.Fence++
			h.Reference.Fence++
		},
		func(o *evidence.NativeOrigin, h *contracts.NativeHello) {
			h.Reference.WorkerID = "22222222-2222-4222-8222-222222222222"
		},
	} {
		wrong, hello := origin, h
		change(&wrong, &hello)
		if c, e := router.Attach(context.Background(), wrong, hello); e == nil || c != nil {
			t.Fatal("changed origin selected original operation")
		}
	}
	conversation, e := router.Attach(context.Background(), origin, h)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = router.Attach(context.Background(), origin, h); e == nil {
		t.Fatal("duplicate connection replaced one attached owner")
	}
	if got, e := registration.Wait(context.Background()); e != nil || got != conversation {
		t.Fatal("exact request lost attached operation", e)
	}
	registration.Close()
	replacement, e := router.Register(context.Background(), origin.Lease.Operation, factory)
	if e != nil {
		t.Fatal("joined slot was not reusable", e)
	}
	registration.Close() // old handles cannot remove the later registration.
	if _, e = router.Register(context.Background(), origin.Lease.Operation, factory); !errors.Is(e, artifact.ErrDownloadCapacity) {
		t.Fatal("old close removed replacement", e)
	}
	replacement.Close()
}

func TestNativeRouterCancellationRetainsBlockedFactoryUntilJoined(t *testing.T) {
	origin, h, _ := routerFixture(t)
	router, e := native.NewHubRouter(1)
	if e != nil {
		t.Fatal(e)
	}
	defer router.Close()
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseFactory := sync.OnceFunc(func() { close(release) })
	defer releaseFactory()
	factory := func(_ context.Context, call context.Context, _ evidence.NativeOrigin, _ contracts.NativeHello) (*native.HubOperation, error) {
		close(entered)
		<-call.Done()
		close(cancelled)
		<-release
		return nil, call.Err()
	}
	registration, e := router.Register(owner, origin.Lease.Operation, factory)
	if e != nil {
		t.Fatal(e)
	}
	attached := make(chan error, 1)
	go func() { _, e := router.Attach(context.Background(), origin, h); attached <- e }()
	<-entered
	cancel()
	<-cancelled
	closed := make(chan struct{})
	go func() { registration.Close(); close(closed) }()
	if _, e = router.Register(context.Background(), origin.Lease.Operation, factory); !errors.Is(e, artifact.ErrDownloadCapacity) {
		t.Fatal("blocking factory released capacity", e)
	}
	select {
	case <-closed:
		t.Fatal("close returned before factory joined")
	default:
	}
	releaseFactory()
	if e = <-attached; e == nil {
		t.Fatal("cancelled registration became attached")
	}
	<-closed
	_, _, next := routerFixture(t)
	replacement, e := router.Register(context.Background(), origin.Lease.Operation, next)
	if e != nil {
		t.Fatal("joined cancellation leaked slot", e)
	}
	replacement.Close()
}
