package native

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
)

type completionBridgeSink struct {
	Stream
	calls int
	until time.Time
	proof nativeCompletionProof
}

func (s *completionBridgeSink) sendCompleted(ctx context.Context, _ contracts.NativeFrame, p nativeCompletionProof) error {
	s.calls++
	s.until, _ = ctx.Deadline()
	s.proof = p
	return ctx.Err()
}

// Only the private zero-byte bridge is exercised here; the paired real H2
// regression runs the unchanged strict server frame/snapshot validation.
func TestNativeCompletionBridgeRetainsBothGatesAndOriginalBound(t *testing.T) {
	for _, mode := range []string{"same", "older-response", "outer-before", "outer-after", "caller-before", "outer-newer", "outer-operation", "outer-certificate", "inner-newer", "wrong-gate", "expired-proof", "expired-inner", "expired-outer", "closed-inner", "closed-outer", "cancelled", "older-nonresponse"} {
		t.Run(mode, func(t *testing.T) {
			lease, _, _, _ := admissionFixture(t)
			now := time.Now()
			lease.Operation.Kind = value.NativeResponse
			lease.Operation.Until = now.Add(8 * time.Second)
			lease.Sequence = 2
			inner, outer := lease, lease
			outer.Sequence = 1
			if mode == "same" {
				outer.Sequence = 2
			}
			if mode == "outer-before" {
				outer.Until = lease.Until.Add(-time.Second)
			}
			if mode == "outer-after" {
				inner.Until = lease.Until.Add(-time.Second)
			}
			switch mode {
			case "outer-newer":
				outer.Sequence = 3
			case "outer-operation":
				outer.Operation.Reference.Fence++
			case "outer-certificate":
				outer.Certificate[0]++
			case "older-nonresponse":
				inner.Operation.Kind = value.NativePrepare
				outer.Operation.Kind = value.NativePrepare
				inner.Operation.Until = inner.Until
				outer.Operation.Until = outer.Until
			}
			clock := now
			gate := func(l value.NativeLease) *evidence.NativeFrameGate {
				g, e := evidence.NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) { return l, nil }, func() time.Time { return clock })
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { g.Close(); g.Wait(context.Background()) })
				return g
			}
			in, out := gate(inner), gate(outer)
			sink := &completionBridgeSink{}
			bridge := &peerStream{Stream: sink, inner: in, outer: out}
			proof := nativeCompletionProof{gate: in, lease: inner}
			ctx, cancel := context.WithDeadline(context.Background(), lease.Until)
			defer cancel()
			switch mode {
			case "inner-newer":
				proof.lease.Sequence--
			case "wrong-gate":
				proof.gate = out
			case "expired-proof":
				proof.lease.Until = now
			case "expired-inner":
				clock = inner.Until
			case "expired-outer":
				clock = outer.Until
			case "closed-inner":
				in.Close()
			case "closed-outer":
				out.Close()
			case "cancelled":
				cancel()
			case "caller-before":
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, now.Add(time.Second))
				defer stop()
			}
			err := bridge.sendCompleted(ctx, contracts.NativeFrame{}, proof)
			positive := mode == "same" || mode == "older-response" || mode == "outer-before" || mode == "outer-after" || mode == "caller-before"
			if !positive {
				if err == nil || sink.calls != 0 {
					t.Fatal("invalid proof reached terminal send", err, sink.calls)
				}
				return
			}
			want := inner.Until
			if outer.Until.Before(want) {
				want = outer.Until
			}
			if d, _ := ctx.Deadline(); d.Before(want) {
				want = d
			}
			if err != nil || sink.calls != 1 || !sink.until.Equal(want) || sink.proof.gate != out || sink.proof.lease != outer {
				t.Fatal("completion lost exact outer snapshot or original minimum", err, sink.calls, sink.until, want)
			}
		})
	}
}

// Exercise the actual unchanged server validator, rather than letting the
// bridge's private sink fixture stand in for the zero-byte frame restriction.
func TestNativeMappedCompletionCannotSendEvidenceOrNonterminalFrames(t *testing.T) {
	for _, mode := range []string{"data", "nonzero", "wrong-phase", "wrong-nonce"} {
		t.Run(mode, func(t *testing.T) {
			lease, _, _, hello := admissionFixture(t)
			lease.Operation.Kind = value.NativeResponse
			lease.Sequence = 2
			in := admissionGate(t, lease)
			outer := lease
			outer.Sequence = 1
			out := admissionGate(t, outer)
			bridge := &peerStream{Stream: &serverStream{gate: out}, inner: in, outer: out}
			a := contracts.NativeAcknowledge{Format: contracts.NativeExchangeFormat, Reference: nativeReference(lease.Operation), Nonce: hello.Nonce, Phase: "joined"}
			kind := contracts.NativeDoneFrame
			switch mode {
			case "data":
				kind = contracts.NativeDataFrame
			case "nonzero":
				a.Bytes = 1
			case "wrong-phase":
				a.Phase = "prepared"
			case "wrong-nonce":
				a.Nonce = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
			}
			payload, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			err = bridge.sendCompleted(context.Background(), contracts.NativeFrame{Kind: kind, Payload: payload}, nativeCompletionProof{gate: in, lease: lease, nonce: hello.Nonce, phase: "joined"})
			if e, ok := err.(interface{ FixedStep() string }); !ok || e.FixedStep() != "proof-frame" {
				t.Fatal("mapped capability reached stream IO or wrong refusal", err)
			}
		})
	}
}
