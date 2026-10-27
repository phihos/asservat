package contextstart

import (
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

type historyVerifierFunc func(context.Context, []byte, fleet.APIContextReceiver) (fleetapp.AuthenticatedHistoryWork, error)

func (f historyVerifierFunc) VerifyHistoryWork(c context.Context, b []byte, r fleet.APIContextReceiver) (fleetapp.AuthenticatedHistoryWork, error) {
	return f(c, b, r)
}

type historyEffectsFunc func(context.Context, capture.HistoryOperationAuthority, capture.HistoryCiphertexts, artifact.Copies) (fleetapp.HistoryReply, error)

func (f historyEffectsFunc) ExecuteHistory(c context.Context, a capture.HistoryOperationAuthority, b capture.HistoryCiphertexts, r artifact.Copies) (fleetapp.HistoryReply, error) {
	return f(c, a, b, r)
}
func historyStreamPair(t *testing.T, ctx context.Context, r fleet.APIContextReceiver) (*frameStream, *frameStream) {
	t.Helper()
	return historyStreamPairContexts(t, ctx, ctx, r)
}
func historyStreamPairContexts(t *testing.T, hubCtx, regionCtx context.Context, r fleet.APIContextReceiver) (*frameStream, *frameStream) {
	t.Helper()
	left, right := net.Pipe()
	makeStream := func(ctx context.Context, c net.Conn) *frameStream {
		s, e := newFrameStream(ctx, r.Channel, func(context.Context) (fleet.APIContextReceiver, error) { return r, nil }, c, c, c.SetReadDeadline, c.SetWriteDeadline, func() error { return nil }, func() { _ = c.Close() })
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	h, g := makeStream(hubCtx, left), makeStream(regionCtx, right)
	t.Cleanup(func() { _ = h.Close(); _ = g.Close() })
	return h, g
}
func historyFixture() (fleetapp.HistoryWork, fleet.APIContextReceiver, capture.HistoryCiphertexts, artifact.Copies) {
	base := workFixture()
	w := base.Work
	n := w.IssuedAt
	e := capture.HistoryExpectation{RootID: w.Channel.RootID, CaptureID: w.CaptureID, Registration: artifact.Registration{Location: artifact.Location{ClusterID: w.Target.ClusterID, ArtifactID: w.CaptureID, AttemptID: w.AttemptID}, StoreID: w.Channel.Hub.ClusterID, AllocationID: w.Channel.ExchangeID, PoolRevision: 1, AllocationRevision: 1, NativeLimit: capture.MaxHistoryParameters, AnchorAt: n.Add(-time.Second), WriteUntil: n.Add(time.Minute), ExpiresAt: n.Add(time.Hour), DeleteBy: n.Add(2 * time.Hour)}, SelectorKey: artifact.Digest{1}, SettingsKey: artifact.Digest{2}, MACVersion: "v1", OriginalExecutionDigest: w.ScopeDigest}
	b := capture.HistoryCiphertexts{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	digest, _ := capture.HistoryCiphertextsDigest(b)
	a := capture.HistoryOperationAuthority{Expectation: e, Operation: "write", RequestID: w.Channel.Challenge, ExecutorEpoch: w.Channel.Executor.ProcessEpoch, StartedAt: n, NotAfter: n.Add(3 * time.Second), BundleDigest: digest}
	var copies artifact.Copies
	for i := range copies {
		copies[i] = artifact.CopyReceipt{VersionID: "v", ETag: "etag", Bytes: 1, SHA256: artifact.Digest{byte(i + 1)}}
	}
	return fleetapp.HistoryWork{Channel: w.Channel, Authority: a}, fleet.APIContextReceiver{Channel: w.Channel, ObservedAt: n, ValidUntil: n.Add(5 * time.Second)}, b, copies
}

// Synthetic effect authority and storage, actual bounded stream framing. Real
// signatures are separately tested; these doubles confer no runtime authority.
func TestHistoryEffectsUseDistinctBoundedStreamAndTypedCompletions(t *testing.T) {
	for _, op := range []string{"write", "read", "purge"} {
		t.Run(op, func(t *testing.T) {
			w, r, b, copies := historyFixture()
			a := &w.Authority
			a.Operation = op
			if op != "write" {
				a.BundleDigest = artifact.Digest{}
				a.CopiesDigest = capture.HistoryCopiesDigest(copies)
			}
			if op == "purge" {
				a.DeletionFence = 1
			}
			ctx, cancel := context.WithDeadline(context.Background(), a.NotAfter)
			defer cancel()
			hub, region := historyStreamPair(t, ctx, r)
			calls := 0
			local := &HistoryLocal{Verifier: historyVerifierFunc(func(_ context.Context, _ []byte, actual fleet.APIContextReceiver) (fleetapp.AuthenticatedHistoryWork, error) {
				if actual.Channel != r.Channel {
					return fleetapp.AuthenticatedHistoryWork{}, fleet.ErrDenied
				}
				return fleetapp.AuthenticatedHistoryWork{Work: w, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: a.StartedAt, ValidUntil: a.NotAfter}, nil
			}), Effects: historyEffectsFunc(func(c context.Context, auth capture.HistoryOperationAuthority, in capture.HistoryCiphertexts, receipts artifact.Copies) (fleetapp.HistoryReply, error) {
				calls++
				if auth != *a || c.Err() != nil {
					t.Error("operation binding changed")
				}
				reply := fleetapp.HistoryReply{Copies: copies}
				switch op {
				case "write":
					if !bytes.Equal(in[0], b[0]) {
						t.Error("ciphertexts changed")
					}
					reply.WriterCompletion = &capture.HistoryWriterCompletion{RootID: a.Expectation.RootID, CaptureID: a.Expectation.CaptureID, AttemptID: a.Expectation.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: a.ExecutorEpoch, ExpectationDigest: capture.HistoryExpectationDigest(a.Expectation), CopiesDigest: capture.HistoryCopiesDigest(copies), CompletedAt: time.Now(), NotAfter: a.NotAfter}
				case "read":
					if receipts != copies {
						t.Error("receipts changed")
					}
					for i := range b {
						reply.Bundle[i] = bytes.Clone(b[i])
					}
				case "purge":
					reply.DeleteCompletion = &capture.HistoryDeleteCompletion{RootID: a.Expectation.RootID, CaptureID: a.Expectation.CaptureID, AttemptID: a.Expectation.Registration.Location.AttemptID, OperationID: a.RequestID, ProcessEpoch: a.ExecutorEpoch, ExpectationDigest: capture.HistoryExpectationDigest(a.Expectation), CopiesDigest: a.CopiesDigest, DeletionFence: a.DeletionFence, CompletedAt: time.Now(), NotAfter: a.NotAfter}
				}
				return reply, nil
			})}
			done := make(chan error, 1)
			go func() {
				f, current, e := region.AwaitWork(ctx)
				if e == nil && f.Kind == contracts.HistoryWorkFrame {
					e = serveRegionalHistory(ctx, region, current, f.Payload, local, time.Now)
				}
				clear(f.Payload)
				done <- e
			}()
			reply, e := serveHubHistory(ctx, hub, w, []byte("synthetic signature"), b, copies, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			if calls != 1 {
				t.Fatal("effect repeated", calls)
			}
			if op == "read" && !bytes.Equal(reply.Bundle[0], b[0]) {
				t.Fatal("ciphertext reply changed")
			}
			reply.Bundle.Clear()
		})
	}
}
func TestHistoryWorkCannotSendCommonOperationFrames(t *testing.T) {
	w, r, _, _ := historyFixture()
	ctx, cancel := context.WithDeadline(context.Background(), w.Authority.NotAfter)
	defer cancel()
	hub, region := historyStreamPair(t, ctx, r)
	done := make(chan error, 1)
	go func() { _, _, e := region.AwaitWork(ctx); done <- e }()
	if e := hub.Send(ctx, contracts.APIContextFrame{Kind: contracts.HistoryWorkFrame, Payload: []byte("synthetic")}); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := hub.Send(ctx, contracts.APIContextFrame{Kind: contracts.APIContextOperationRequestFrame, Payload: []byte("{}")}); e == nil {
		t.Fatal("common operation entered history session")
	}
}

func TestHistoryPeerDisconnectCancelsAndJoinsRegionalEffect(t *testing.T) {
	w, r, b, copies := historyFixture()
	hubCtx, stopHub := context.WithDeadline(context.Background(), w.Authority.NotAfter)
	defer stopHub()
	regionCtx, stopRegion := context.WithDeadline(context.Background(), w.Authority.NotAfter)
	defer stopRegion()
	hub, region := historyStreamPairContexts(t, hubCtx, regionCtx, r)
	entered := make(chan struct{})
	canceled := make(chan struct{})
	local := &HistoryLocal{Verifier: historyVerifierFunc(func(context.Context, []byte, fleet.APIContextReceiver) (fleetapp.AuthenticatedHistoryWork, error) {
		return fleetapp.AuthenticatedHistoryWork{Work: w, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: w.Authority.StartedAt, ValidUntil: w.Authority.NotAfter}, nil
	}), Effects: historyEffectsFunc(func(ctx context.Context, _ capture.HistoryOperationAuthority, _ capture.HistoryCiphertexts, _ artifact.Copies) (fleetapp.HistoryReply, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return fleetapp.HistoryReply{}, ctx.Err()
	})}
	regional := make(chan error, 1)
	go func() {
		f, current, e := region.AwaitWork(regionCtx)
		if e == nil {
			e = serveRegionalHistory(regionCtx, region, current, f.Payload, local, time.Now)
		}
		clear(f.Payload)
		regional <- e
	}()
	result := make(chan error, 1)
	go func() { _, e := serveHubHistory(hubCtx, hub, w, []byte("synthetic"), b, copies, time.Now); result <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("effect did not start")
	}
	stopHub()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("regional effect retained after actual peer disconnect")
	}
	if e := <-result; e == nil {
		t.Fatal("canceled operation returned success")
	}
	if e := <-regional; e == nil {
		t.Fatal("disconnected operation returned success")
	}
}

func TestHistoryEmptyReceiptsRequireExpiredUnclaimedPurge(t *testing.T) {
	w, _, b, copies := historyFixture()
	a := w.Authority
	a.Operation = "purge"
	a.BundleDigest = artifact.Digest{}
	a.CopiesDigest = capture.HistoryCopiesDigest(artifact.Copies{})
	a.DeletionFence = 1
	a.Expectation.Registration.WriteUntil = a.StartedAt
	if _, err := historyRequest(a, b, artifact.Copies{}); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"read", "write"} {
		other := a
		other.Operation = op
		if fleetapp.HistoryCopiesMatch(other, artifact.Copies{}) {
			t.Fatal("empty receipts admitted for", op)
		}
	}
	early := a
	early.StartedAt = a.StartedAt.Add(-time.Microsecond)
	if _, err := historyRequest(early, b, artifact.Copies{}); err == nil {
		t.Fatal("cleanup before original writer bound")
	}
	partial := artifact.Copies{}
	partial[0] = copies[0]
	a.CopiesDigest = capture.HistoryCopiesDigest(partial)
	if _, err := historyRequest(a, b, partial); err == nil {
		t.Fatal("partial receipts accepted")
	}
	a.CopiesDigest = artifact.Digest{99}
	if _, err := historyRequest(a, b, artifact.Copies{}); err == nil {
		t.Fatal("different cleanup digest accepted")
	}
}
