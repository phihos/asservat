package bootstrap

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	execution "asservat.local/asservat/internal/domain/execution"
)

func TestProcessNodeCancellationJoinsAcquirerBeforeFailureReceipt(t *testing.T) {
	_, q, e, pin, now := processHolderFixture(t)
	p := collector.ProcessCapture{CaptureID: e.CaptureUID, CollectorEpoch: q.node.Epoch, ExpectationDigest: artifact.Digest{1}, Request: execution.ProcessSnapshotRequest{Pin: pin, NodeUID: q.node.NodeUID, NodeBootID: q.node.BootID, Mode: artifact.ProcessAll, NativeLimit: artifact.ProcessNativeLimit, NotBefore: now, Deadline: now.Add(5 * time.Second)}}
	w := collector.Work{ID: e.CaptureUID, Sequence: 1, Kind: collector.WorkProcesses, NotAfter: now.Add(time.Second), Processes: &p}
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var mu sync.Mutex
	budget, err := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	uploaded := make(chan collector.ProcessResult, 1)
	n := &nodeProfiles{identity: func() collector.Identity { return q.node }, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &mu, processes: func(ctx context.Context, _ collector.ProcessCapture) (artifact.ProcessInventory, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return artifact.ProcessInventory{}, ctx.Err()
	}, uploadProcesses: func(_ context.Context, _ string, r collector.ProcessResult, body io.Reader) error {
		b, err := io.ReadAll(body)
		if err != nil || len(b) != 0 {
			t.Error("canceled source emitted native", err)
		}
		uploaded <- r
		return nil
	}}
	if r := n.startProcesses(t.Context(), q.node.Epoch, w); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("source did not start")
	}
	bad := collector.Work{ID: e.CaptureUID, Sequence: 2, Kind: collector.WorkCancelProcesses, NotAfter: now.Add(time.Second), CancelProcesses: &collector.PacketCancel{CaptureID: e.CaptureUID, WorkID: "22222222-2222-4222-8222-222222222222"}}
	if n.stop(bad).Outcome == collector.OutcomeAccepted {
		t.Fatal("replacement work canceled original")
	}
	good := bad
	good.CancelProcesses = &collector.PacketCancel{CaptureID: p.CaptureID, WorkID: w.ID}
	if n.stop(good).Outcome != collector.OutcomeAccepted {
		t.Fatal("original stop refused")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("source context not canceled")
	}
	select {
	case <-uploaded:
		t.Fatal("failure reported before source join")
	default:
	}
	close(release)
	n.wg.Wait()
	result := <-uploaded
	if !result.Valid() || result.NativeBytes != 0 || result.Failure != collector.ReasonCaptureFailed {
		t.Fatal("untruthful joined failure", result)
	}
	mu.Lock()
	usage := budget.Usage(now)
	running := len(n.running)
	mu.Unlock()
	if usage.FrozenReserved != 0 || running != 0 {
		t.Fatal("joined source leaked budget", usage, running)
	}
	if n.startProcesses(t.Context(), q.node.Epoch, w).Outcome == collector.OutcomeAccepted {
		t.Fatal("stopped acquisition replayed")
	}
}
