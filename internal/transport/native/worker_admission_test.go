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
	native "asservat.local/asservat/internal/transport/native"
)

const hubWorkerOtherID = "22222222-2222-4222-8222-222222222222"

// Synthetic worker checks: the origin, idle result and recheck are explicit
// values; the production admission, router and registration are exercised.
type hubWorkerPeers struct {
	origin   evidence.NativeOrigin
	idle     *evidence.NativeIdle
	worker   atomic.Int32
	rechecks atomic.Int32
}

func (p *hubWorkerPeers) CheckWorkerNative(_ context.Context, state *tls.ConnectionState, h contracts.NativeHello) (evidence.NativeOrigin, error) {
	p.worker.Add(1)
	if state == nil || len(state.PeerCertificates) != 1 || h.Reference != workerHello().Reference || len(h.WorkerLeaf) != 0 {
		return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
	}
	if p.idle != nil {
		return evidence.NativeOrigin{}, p.idle
	}
	return p.origin, nil
}
func (p *hubWorkerPeers) CheckForwardedNative(context.Context, *tls.ConnectionState, contracts.NativeHello) (evidence.NativeOrigin, error) {
	return evidence.NativeOrigin{}, contracts.ErrNativeProtocol
}
func (p *hubWorkerPeers) RecheckWorkerNative(_ context.Context, _ *tls.ConnectionState, origin evidence.NativeOrigin) (value.NativeLease, error) {
	p.rechecks.Add(1)
	return origin.Lease, nil
}
func (p *hubWorkerPeers) RecheckForwardedNative(context.Context, *tls.ConnectionState, evidence.NativeOrigin) (value.NativeLease, error) {
	return value.NativeLease{}, contracts.ErrNativeProtocol
}

// hubWorkerServing mirrors the production owner check: only an operation of
// this exact Pod/process is served here.
type hubWorkerServing struct {
	until      time.Time
	pod        string
	denyServer bool
	hub        atomic.Int32
}

func (s *hubWorkerServing) CheckOwnerServing(context.Context) (time.Time, error) {
	if s.denyServer {
		return time.Time{}, artifact.ErrDownloadUnavailable
	}
	return s.until, nil
}
func (s *hubWorkerServing) CheckNativeHub(_ context.Context, o value.NativeOperation) (time.Time, error) {
	s.hub.Add(1)
	if o.HubPodUID != s.pod || o.HubProcessEpoch != nativeID {
		return time.Time{}, artifact.ErrDownloadUnavailable
	}
	return s.until, nil
}

func TestHubWorkerAdmissionAttachesOnlyThisProcessOperation(t *testing.T) {
	for _, mode := range []string{"own", "foreign-owner", "separate-connector", "idle", "serving-unavailable", "forwarded-hello"} {
		t.Run(mode, func(t *testing.T) {
			// Longer than the synthetic operation, whose own Until bounds it.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			origin, attached, factory := routerFixture(t)
			router, err := native.NewHubRouter(1)
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			registration, err := router.Register(ctx, origin.Lease.Operation, factory)
			if err != nil {
				t.Fatal(err)
			}
			defer registration.Close()
			peers := &hubWorkerPeers{origin: origin}
			// The synthetic operation gate returns the original lease, so a
			// serving bound beyond it keeps that lease attachable unchanged.
			serving := &hubWorkerServing{until: origin.Lease.Until.Add(time.Second), pod: nativeID}
			hello := workerHello()
			switch mode {
			case "foreign-owner":
				serving.pod = hubWorkerOtherID
			case "separate-connector":
				peers.origin.Lease.Operation.Path.ConnectorClusterID = hubWorkerOtherID
			case "idle":
				peers.idle = syntheticNativeIdle(t)
				serving.until = time.Now().Add(2 * time.Second)
			case "serving-unavailable":
				serving.denyServer = true
			case "forwarded-hello":
				hello.Reference.OperationID, hello.Reference.Fence = nativeID, 1
			}
			a, err := native.NewHubWorkerAdmission(peers, serving, router, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
			conversation, err := a.OpenNative(ctx, state, hello)
			if mode == "own" {
				if err != nil || conversation == nil {
					t.Fatal("own operation was not attached", err)
				}
				defer conversation.Close()
				lease, e := conversation.Gate().Check(ctx)
				if e != nil || !lease.Operation.Equal(origin.Lease.Operation) || lease.Until.After(serving.until) || peers.rechecks.Load() == 0 {
					t.Fatal("frame gate did not recheck the worker and owner or extended serving", e)
				}
				if again, e := router.Attach(ctx, origin, attached); e == nil || again != nil {
					t.Fatal("one registration attached twice")
				}
				return
			}
			if conversation != nil {
				conversation.Close()
				t.Fatal("conversation outside this process's own hub-local operation", mode)
			}
			if mode == "idle" {
				var idle *evidence.NativeIdle
				if !errors.As(err, &idle) || idle.Until.After(serving.until) {
					t.Fatal("idle was not returned within the serving bound", err)
				}
				return
			}
			if err == nil {
				t.Fatal("refused admission returned no error", mode)
			}
			if mode == "separate-connector" && serving.hub.Load() != 0 {
				t.Fatal("a path with another connector reached the owner check")
			}
			// The refusal names its closed stage for the operator report only.
			var fixed interface{ FixedStep() string }
			want := map[string]string{"foreign-owner": "hub", "separate-connector": "path", "serving-unavailable": "serving", "forwarded-hello": "hello"}[mode]
			if !errors.As(err, &fixed) || fixed.FixedStep() != want {
				t.Fatal("refusal stage missing", mode, err)
			}
			if (mode == "serving-unavailable" || mode == "forwarded-hello") && peers.worker.Load() != 0 {
				t.Fatal("worker proof read before serving/shape checks")
			}
			// A refused attempt consumed nothing: the exact owner still attaches.
			if again, e := router.Attach(ctx, origin, attached); e != nil || again == nil {
				t.Fatal("refused admission consumed the registration", e)
			} else {
				again.Close()
			}
		})
	}
}
