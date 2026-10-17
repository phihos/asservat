package native_test

import (
	"context"
	"encoding/json"
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

type closingSQLStream struct {
	native.Stream
	released <-chan struct{}
	terminal *atomic.Bool
	received chan<- struct{}
	mutate   func(*contracts.NativeFrame)
}

func (s closingSQLStream) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, e := s.Stream.Receive(ctx)
	if e == nil && f.Kind == contracts.NativeDoneFrame {
		a, err := contracts.DecodeNativeAcknowledge(f.Payload)
		if err == nil && a.Phase == "joined" {
			s.terminal.Store(true)
			s.received <- struct{}{}
			select {
			case <-s.released:
			case <-ctx.Done():
				clear(f.Payload)
				return contracts.NativeFrame{}, ctx.Err()
			}
			if s.mutate != nil {
				s.mutate(&f)
			}
		}
	}
	return f, e
}

// The hub caller retires its original SQL owner immediately after successful
// acknowledgement. Delay only the connector's final marker forwarding until
// that legitimate retirement is visible; all actual evidence frames retain
// normal fresh authority checks. The authority state is synthetic, h2 is real.
func TestNativeContentFinalMarkerSurvivesOwnPositiveRetirement(t *testing.T) {
	for _, mode := range []string{"own-retirement", "known-revocation", "known-cancellation", "upstream-cancellation", "known-shortening", "wrong-phase", "wrong-reference", "nonzero-bytes", "nonterminal"} {
		t.Run(mode, func(t *testing.T) { runContentClosure(t, mode) })
	}
}
func runContentClosure(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source := flowSourceValue(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	result, e := evidence.NewRegionalContextResult(ctx, target, &flowSource{}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()
	prep, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	m, e := prep.Prepared(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = prep.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	prep.Close()
	now = time.Now()
	a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
	lease := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Length: m.Size, StartedAt: now, Until: a.ValidUntil, Authority: a}
	released := make(chan struct{})
	var terminal, closed, short atomic.Bool
	gateCreated := make(chan *evidence.NativeFrameGate, 1)
	received := make(chan struct{}, 1)
	upstream := make(chan native.Stream, 1)
	response, client, _ := flowOperationWithConnector(t, ctx, source, value.NativeResponse, 3, lease, func(a *flowAdmission) native.Admission {
		a.check = func(context.Context) (value.NativeLease, error) {
			if closed.Load() {
				return value.NativeLease{}, artifact.ErrDownloadUnavailable
			}
			l := a.lease
			if short.Load() {
				l.Until = time.Now().Add(20 * time.Millisecond)
			}
			return l, nil
		}
		a.observedGate = func(g *evidence.NativeFrameGate) { gateCreated <- g }
		a.wrap = func(s native.Stream) native.Stream {
			upstream <- s
			return closingSQLStream{s, released, &terminal, received, func(f *contracts.NativeFrame) {
				if mode == "nonterminal" {
					f.Kind = contracts.NativeDataFrame
					return
				}
				ack, e := contracts.DecodeNativeAcknowledge(f.Payload)
				if e != nil {
					return
				}
				switch mode {
				case "wrong-phase":
					ack.Phase = "prepared"
				case "wrong-reference":
					ack.Reference.Fence++
				case "nonzero-bytes":
					ack.Bytes = 1
				}
				clear(f.Payload)
				f.Payload, _ = json.Marshal(ack)
			}}
		}
		return a
	})
	done = flowRunWorker(t, ctx, client, target, result)
	chunk, e := response.ReadChunk(ctx, lease, 0, m.Size)
	if e != nil {
		t.Fatal(e)
	}
	if string(chunk.Bytes) != string(flowBody) {
		t.Fatal("native payload changed")
	}
	clear(chunk.Bytes)
	if e = response.AcknowledgeNativeChunk(ctx, lease, 0, m.Size); e != nil {
		t.Fatal(e)
	}
	response.Close()
	connectorGate := <-gateCreated
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("final marker never reached held connector", ctx.Err())
	}
	switch mode {
	case "known-revocation":
		closed.Store(true)
		if _, e = connectorGate.Check(ctx); e == nil {
			t.Fatal("known SQL denial accepted")
		}
	case "known-cancellation":
		connectorGate.Close()
	case "upstream-cancellation":
		if e = (<-upstream).Close(); e != nil {
			t.Fatal(e)
		}
	case "known-shortening":
		short.Store(true)
		l, err := connectorGate.Check(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wait, stop := context.WithDeadline(ctx, l.Until)
		<-wait.Done()
		stop()
	default:
		closed.Store(true)
	}
	close(released)
	e = <-done
	if mode == "own-retirement" && e != nil {
		t.Fatal("positive content acknowledgement did not join worker", e)
	}
	if mode != "own-retirement" && e == nil {
		t.Fatal("invalid final marker or lost gate claimed Joined", mode)
	}
	if !terminal.Load() {
		t.Fatal("test never held actual final marker")
	}
}
