package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"bytes"
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"
)

type responseProofReader struct {
	proof func() NativeResponsePeerProof
	calls *atomic.Int32
}

func (r responseProofReader) ReadDownloadPeerProof(context.Context, string, value.KeyPeer) (value.KeyWorkerProof, error) {
	r.calls.Add(1)
	return r.proof().Proof, nil
}
func (r responseProofReader) ReadNativeResponsePeerProof(context.Context, string, value.KeyPeer) (NativeResponsePeerProof, error) {
	r.calls.Add(1)
	return r.proof(), nil
}

type responseLocatorFunc func(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error)

func (f responseLocatorFunc) LocateNativeOperation(c context.Context, i, s, w string, p value.KeyPeer) (value.NativeLease, error) {
	return f(c, i, s, w, p)
}

type responseObservationFunc func(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error)

func (f responseObservationFunc) ObserveNativeOperation(c context.Context, r value.NativeReference, p value.KeyPeer) (value.NativeLease, error) {
	return f(c, r, p)
}

// SQL/proof authority is synthetic. The test checks ownership semantics, not
// a Kubernetes token signature or the native provider qualification.
func TestNativeResponseRetainsInitialBindingAndActualExpiryWithoutReattestation(t *testing.T) {
	base := nativeLeaseFixture()
	base.Operation.Kind = value.NativeResponse
	base.Operation.Until = base.Operation.StartedAt.Add(20 * time.Second)
	base.Operation.Processing.ValidUntil = base.Operation.StartedAt.Add(5 * time.Second)
	start := base.Operation.StartedAt
	var elapsed atomic.Int64
	now := func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	id := base.Operation.Reference.InstallationID
	peer := value.KeyPeer{InstallationID: id, PeerID: id, Role: "acquisition", Certificate: base.Certificate, NotBefore: start.Add(-time.Minute), NotAfter: start.Add(time.Minute)}
	initial := value.KeyWorkerProof{Binding: value.KeyWorkerBinding{InstallationID: id, DownloadID: id, ClusterID: id, Namespace: "workers", NamespaceUID: "namespace", ServiceAccount: "reader", ServiceAccountUID: "account", Job: "download", JobUID: "job", Pod: "worker", PodUID: id, JobSpec: artifact.Digest{1}, PodSpec: artifact.Digest{2}}, Peer: peer, TokenDigest: artifact.Digest{3}, ObservedAt: start, FreshUntil: start.Add(4 * time.Second)}
	var calls, observations atomic.Int32
	reader := responseProofReader{calls: &calls, proof: func() NativeResponsePeerProof {
		return NativeResponsePeerProof{Proof: initial, TokenNotAfter: start.Add(15 * time.Second)}
	}}
	service := NativeOrigins{Now: now, Proofs: func(DownloadPeerToken) (DownloadPeerProofReader, error) { return reader, nil }, Locators: responseLocatorFunc(func(context.Context, string, string, string, value.KeyPeer) (value.NativeLease, error) {
		return base, nil
	}), Operations: responseObservationFunc(func(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error) {
		observations.Add(1)
		l := base
		l.ObservedAt = now()
		l.Until = now().Add(5 * time.Second)
		return l, nil
	})}
	origin, err := service.Check(t.Context(), id, id, id, peer, []byte("protected-worker-token"))
	if err != nil {
		t.Fatal(err)
	}
	elapsed.Store(int64(12 * time.Second))
	renewed, err := service.Recheck(t.Context(), origin)
	if err != nil || !renewed.Until.Equal(start.Add(15*time.Second)) || calls.Load() != 1 || observations.Load() != 1 {
		t.Fatal("initial admission/actual expiry not preserved", err, calls.Load(), observations.Load(), renewed.Until)
	}
	if origin.Proof.Valid(now()) || origin.Proof.FreshUntil != initial.FreshUntil {
		t.Fatal("initial key-binding proof dates extended")
	}
	encoded, _ := json.Marshal(origin)
	if bytes.Contains(encoded, []byte("TokenNotAfter")) {
		t.Fatal("local actual token expiry became wire authority")
	}
	var replay NativeOrigin
	if json.Unmarshal(encoded, &replay) != nil {
		t.Fatal("test origin decode")
	}
	if _, err = service.Recheck(t.Context(), replay); err == nil {
		t.Fatal("serialized origin invented local admission")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = service.Recheck(canceled, origin); err == nil {
		t.Fatal("canceled response continued")
	}
	elapsed.Store(int64(15 * time.Second))
	if _, err = service.Recheck(t.Context(), origin); err == nil {
		t.Fatal("actual token expiry ignored")
	}
	// A provider without the purpose-specific reviewed expiry cannot authorize
	// a long response by returning an ordinary short proof.
	elapsed.Store(0)
	service.Proofs = func(DownloadPeerToken) (DownloadPeerProofReader, error) {
		return peerProofFunc(func(context.Context, string, value.KeyPeer) (value.KeyWorkerProof, error) { return initial, nil }), nil
	}
	if _, err = service.Check(t.Context(), id, id, id, peer, []byte("protected-worker-token")); err == nil {
		t.Fatal("missing reviewed expiry accepted")
	}
}

func TestNativeResponseGateRejectsKnownSequenceDowngrade(t *testing.T) {
	l := nativeLeaseFixture()
	l.Operation.Kind = value.NativeResponse
	var sequence atomic.Int64
	sequence.Store(1)
	gate, err := NewNativeFrameGate(t.Context(), func(context.Context) (value.NativeLease, error) {
		copy := l
		copy.Sequence = sequence.Load()
		return copy, nil
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	sequence.Store(2)
	if got, err := gate.Check(t.Context()); err != nil || got.Sequence != 2 {
		t.Fatal("acknowledged newer sequence refused", err)
	}
	sequence.Store(1)
	if _, err := gate.Check(t.Context()); err == nil {
		t.Fatal("known sequence rolled back")
	}
}
