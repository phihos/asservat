package native_test

import (
	"context"
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

type cancelledFlowRead struct {
	entered, joined chan struct{}
	calls           atomic.Int32
}

func (r *cancelledFlowRead) ReadNativeContext(ctx context.Context, _ evidence.NativeContextSource, _ value.NativeOperation, _ string, _ time.Time) ([]byte, error) {
	r.calls.Add(1)
	close(r.entered)
	<-ctx.Done()
	close(r.joined)
	return nil, ctx.Err()
}
func TestNativeTwoHopCloseCancelsAndJoinsRegionalRead(t *testing.T) {
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
	operation, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
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

type losePreparedFinal struct {
	contracts.NativeStream
	lost atomic.Bool
}

func (s *losePreparedFinal) Receive(ctx context.Context) (contracts.NativeFrame, error) {
	f, e := s.NativeStream.Receive(ctx)
	if e == nil && f.Kind == contracts.NativeDoneFrame && !s.lost.Swap(true) {
		clear(f.Payload)
		_ = s.NativeStream.Close()
		return contracts.NativeFrame{}, errors.New("synthetic lost final acknowledgement")
	}
	return f, e
}
func TestNativeLostFinalAcknowledgementNeverReturnsJoined(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	n := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: n, RunUntil: n.Add(time.Minute)}
	reader := &flowSource{}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	operation, client, op := flowOperation(t, ctx, flowSourceValue(t), value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	stream, e := client.Open(ctx, workerHello())
	if e != nil {
		t.Fatal(e)
	}
	lossy := &losePreparedFinal{NativeStream: stream}
	type outcome struct {
		state contracts.NativeConversationResult
		err   error
	}
	worker := make(chan outcome, 1)
	go func() {
		s, e := native.RunWorkerConversation(ctx, lossy, workerHello(), target, artifact.Digest{1}, result)
		worker <- outcome{s, e}
	}()
	if _, e = operation.Prepared(ctx); e != nil {
		t.Fatal(e)
	}
	_ = operation.Commit(ctx) // final transport acknowledgement can be uncertain.
	select {
	case out := <-worker:
		if out.err == nil || out.state.State != contracts.NativeUncertain || out.state.Reference.OperationID != op.Reference.OperationID || !lossy.lost.Load() {
			t.Fatal("lost acknowledgement permitted new work", out)
		}
	case <-ctx.Done():
		t.Fatal("uncertain worker conversation did not join")
	}
	if reader.reads.Load() != 1 {
		t.Fatal("uncertainty caused another decrypt")
	}
}
