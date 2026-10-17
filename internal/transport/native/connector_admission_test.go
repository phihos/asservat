package native_test

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// These test peers supply explicit synthetic authority to the real production
// ConnectorAdmission constructor. Actual two-hop h2/TLS and closure stay real.
type connectorAdmissionPeers struct{ a *flowAdmission }

func (p connectorAdmissionPeers) CheckWorkerNative(_ context.Context, state *tls.ConnectionState, _ contracts.NativeHello) (evidence.NativeOrigin, error) {
	if state == nil || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) != 1 {
		return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
	}
	return evidence.NativeOrigin{Lease: p.a.lease}, nil
}
func (p connectorAdmissionPeers) CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
}
func (p connectorAdmissionPeers) RecheckWorkerNative(_ context.Context, _ *tls.ConnectionState, origin evidence.NativeOrigin) (value.NativeLease, error) {
	return origin.Lease, nil
}
func (p connectorAdmissionPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return value.NativeLease{}, contracts.ErrNativeProtocol
}

type connectorAdmissionServing struct{ until time.Time }

func (s connectorAdmissionServing) CheckNativeConnector(context.Context) (time.Time, error) {
	return s.until, nil
}

type connectorAdmissionForwarder struct{ a *flowAdmission }

func (f connectorAdmissionForwarder) OpenNativeOwner(_ context.Context, origin evidence.NativeOrigin, hello contracts.NativeHello) (contracts.NativeStream, *evidence.NativeFrameGate, error) {
	stream, e := f.a.upstream.Open(f.a.owner, hello)
	if e != nil {
		return nil, nil, e
	}
	gate, e := evidence.NewNativeFrameGate(f.a.owner, func(context.Context) (value.NativeLease, error) { return origin.Lease, nil }, time.Now)
	if e != nil {
		stream.Close()
		return nil, nil, e
	}
	return stream, gate, nil
}
func TestNativeProductionConnectorAdmissionJoinsRegionalRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	source := flowSourceValue(t)
	reader := &cancelledFlowRead{entered: make(chan struct{}), joined: make(chan struct{})}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	operation, client, _ := flowOperationWithConnector(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{}, func(a *flowAdmission) native.Admission {
		c, e := native.NewConnectorAdmission(connectorAdmissionPeers{a}, connectorAdmissionServing{a.lease.Until}, connectorAdmissionForwarder{a}, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		return c
	})
	stream, e := client.Open(ctx, workerHello())
	if e != nil {
		t.Fatal(e)
	}
	type outcome struct {
		state contracts.NativeConversationResult
		err   error
	}
	worker := make(chan outcome, 1)
	go func() {
		s, e := native.RunWorkerConversation(ctx, stream, workerHello(), target, artifact.Digest{1}, result)
		worker <- outcome{s, e}
	}()
	select {
	case <-reader.entered:
	case <-ctx.Done():
		t.Fatal("regional read never started")
	}
	closed := make(chan error, 1)
	go func() { closed <- operation.Close() }()
	select {
	case <-reader.joined:
	case <-time.After(time.Second):
		t.Fatal("two-hop disconnect did not cancel regional read")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("hub close did not join streams")
	}
	select {
	case out := <-worker:
		if out.err == nil || out.state.State != contracts.NativeUncertain {
			t.Fatal("cancelled read claimed a joined operation", out)
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not join")
	}
	if reader.calls.Load() != 1 {
		t.Fatal("cancelled native read repeated")
	}
}
