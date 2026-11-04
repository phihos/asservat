package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

func TestNodeProfilePreservesKnownUnavailableAndBusyWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		want    collector.Reason
	}{
		{"unavailable", execution.ErrProfileUnavailable, collector.Reason("ProfileUnavailable")},
		{"wrapped-unavailable", fmt.Errorf("acquisition: %w", execution.ErrProfileUnavailable), collector.Reason("ProfileUnavailable")},
		{"busy", execution.ErrProfilerBusy, collector.ReasonCaptureBusy},
		{"generic", errors.New("unknown acquisition failure"), collector.ReasonCaptureFailed},
		{"same-text", errors.New(execution.ErrProfileUnavailable.Error()), collector.ReasonCaptureFailed},
		{"cancelled", context.Canceled, collector.ReasonCaptureFailed},
		{"limit", execution.ErrProfileLimit, collector.ReasonCaptureFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, q, reader, e, _, now := profileHolderFixture(t)
			p := collector.ProfileCapture{CaptureID: e.CaptureUID, CollectorEpoch: q.node.Epoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: reader.plan.AddressMode, Address: reader.plan.RouteIP, Port: reader.plan.Port, Host: "localhost", Request: execution.GoProfileRequest{Binding: e.Binding(), Pin: reader.plan.Pin, NodeUID: q.node.NodeUID, NodeBootID: q.node.BootID, SourceRef: "pprof", EndpointDigest: e.Profile.EndpointDigest, Parameters: reader.plan.Parameters, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(5 * time.Second)}}
			w := collector.Work{ID: e.CaptureUID, Sequence: 1, Kind: collector.WorkProfileCapture, NotAfter: now.Add(time.Second), Profile: &p}
			budget, err := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			calls, uploads := 0, 0
			var result collector.ProfileResult
			n := &nodeProfiles{identity: func() collector.Identity { return q.node }, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &mu,
				acquire: func(context.Context, collector.ProfileCapture, []byte, io.Writer) (execution.GoProfileOutcome, error) {
					calls++
					return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true}, tc.failure
				},
				upload: func(_ context.Context, _ string, r collector.ProfileResult, body io.Reader) error {
					uploads++
					result = r
					b, err := io.ReadAll(body)
					if err != nil || len(b) != 0 {
						t.Error("refusal delivered native bytes", err)
					}
					return nil
				}}
			if r := n.start(t.Context(), q.node.Epoch, w, nil, false); r.Outcome != collector.OutcomeAccepted {
				t.Fatal(r)
			}
			n.wg.Wait()
			if result.Failure != tc.want || !result.Valid() || result.Outcome.ResponseComplete || result.Outcome.NativeBytes != 0 || !result.Outcome.MayHaveStarted {
				t.Fatal("typed refusal or uncertainty lost", result)
			}
			mu.Lock()
			held := n.running[p.Request.Pin.UID]
			usage := budget.Usage(now)
			mu.Unlock()
			if !held.uncertainUntil.Equal(p.Request.Deadline) || usage.FrozenReserved != 0 {
				t.Fatal("refusal changed original uncertain lifetime or leaked joined memory", held, usage)
			}
			if r := n.start(t.Context(), q.node.Epoch, w, nil, false); r.Outcome == collector.OutcomeAccepted {
				t.Fatal("refused acquisition replayed")
			}
			n.wg.Wait()
			if calls != 1 || uploads != 1 {
				t.Fatal("refusal retried", calls, uploads)
			}
		})
	}
}

func TestNodeProfileOwnsBudgetAndRejectsReplay(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	request := execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: id, ArtifactID: id, AttemptID: id, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: id, Name: "app-0", UID: id, NodeName: "node"}, NodeUID: id, NodeBootID: id, SourceRef: "pprof", EndpointDigest: artifact.Digest{3}, Parameters: execution.GoProfileParameters{Type: "heap", Mode: "snapshot"}, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(5 * time.Second)}
	profile := collector.ProfileCapture{CaptureID: id, CollectorEpoch: id, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: "targetLoopback", Address: netip.MustParseAddr("127.0.0.1"), Port: 6060, Host: "localhost", Request: request}
	work := collector.Work{ID: id, Sequence: 1, Kind: collector.WorkProfileCapture, NotAfter: now.Add(time.Second), Profile: &profile}
	budget, err := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	entered, release, uploaded := make(chan struct{}), make(chan struct{}), make(chan []byte, 1)
	n := &nodeProfiles{identity: func() collector.Identity {
		return collector.Identity{NodeUID: id, NodeName: "node", BootID: id, Epoch: id}
	}, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu,
		acquire: func(ctx context.Context, p collector.ProfileCapture, _ []byte, w io.Writer) (execution.GoProfileOutcome, error) {
			close(entered)
			<-release
			_, err := w.Write([]byte("native"))
			return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: time.Now().UTC(), MayHaveStarted: true, ResponseComplete: err == nil, NativeBytes: 6}, err
		},
		upload: func(ctx context.Context, _ string, r collector.ProfileResult, source io.Reader) error {
			if !r.Valid() {
				t.Error("invalid node result", r)
			}
			b, err := io.ReadAll(source)
			uploaded <- b
			return err
		}}
	if got := n.start(context.Background(), id, work, nil, false); got.Outcome != collector.OutcomeAccepted {
		t.Fatal(got)
	}
	<-entered
	if got := n.start(context.Background(), id, work, nil, false); got.Outcome == collector.OutcomeAccepted {
		t.Fatal("replay acquired")
	}
	mu.Lock()
	held := budget.Usage(time.Now()).FrozenReserved
	mu.Unlock()
	if held != request.NativeLimit {
		t.Fatal("native buffer unreserved", held)
	}
	close(release)
	n.wg.Wait()
	if got := string(<-uploaded); got != "native" {
		t.Fatal(got)
	}
	mu.Lock()
	held = budget.Usage(time.Now()).FrozenReserved
	mu.Unlock()
	if held != 0 {
		t.Fatal("joined buffer leaked", held)
	}
	if got := n.start(context.Background(), id, work, nil, false); got.Outcome == collector.OutcomeAccepted {
		t.Fatal("completed acquisition replayed")
	}
}

func TestNodeProfileCancelKeepsUncertainRuntimeSlotUntilOriginalDeadline(t *testing.T) {
	h, q, reader, e, _, now := profileHolderFixture(t)
	_ = h
	p := collector.ProfileCapture{CaptureID: e.CaptureUID, CollectorEpoch: q.node.Epoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: reader.plan.AddressMode, Address: reader.plan.RouteIP, Port: reader.plan.Port, Host: "localhost", Request: execution.GoProfileRequest{Binding: e.Binding(), Pin: reader.plan.Pin, NodeUID: q.node.NodeUID, NodeBootID: q.node.BootID, SourceRef: "pprof", EndpointDigest: e.Profile.EndpointDigest, Parameters: reader.plan.Parameters, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(5 * time.Second)}}
	w := collector.Work{ID: e.CaptureUID, Sequence: 1, Kind: collector.WorkProfileCapture, NotAfter: now.Add(time.Second), Profile: &p}
	budget, err := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	entered := make(chan struct{})
	n := &nodeProfiles{identity: func() collector.Identity { return q.node }, now: func() time.Time { return now }, budget: func() *collector.Budget { return budget }, budgetMu: &mu,
		acquire: func(ctx context.Context, _ collector.ProfileCapture, _ []byte, _ io.Writer) (execution.GoProfileOutcome, error) {
			close(entered)
			<-ctx.Done()
			return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true}, ctx.Err()
		},
		upload: func(_ context.Context, _ string, r collector.ProfileResult, _ io.Reader) error {
			if r.Failure == "" || !r.Valid() {
				t.Error("uncertain failure lost", r)
			}
			return nil
		}}
	if r := n.start(context.Background(), q.node.Epoch, w, nil, false); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	<-entered
	cancel := collector.Work{ID: "22222222-2222-4222-8222-222222222222", Sequence: 2, Kind: collector.WorkCancelProfileCapture, NotAfter: now.Add(time.Second), CancelProfile: &collector.PacketCancel{CaptureID: p.CaptureID, WorkID: w.ID}}
	if r := n.stop(cancel); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	n.wg.Wait()
	mu.Lock()
	usage := budget.Usage(now)
	held := n.running[p.Request.Pin.UID]
	mu.Unlock()
	if usage.FrozenReserved != 0 || !held.uncertainUntil.Equal(p.Request.Deadline) {
		t.Fatal("uncertain runtime slot or joined memory lost", usage, held)
	}
	second := p
	second.CaptureID = "33333333-3333-4333-8333-333333333333"
	w.Profile = &second
	w.ID = second.CaptureID
	if r := n.start(context.Background(), q.node.Epoch, w, nil, false); r.Reason != collector.ReasonCaptureBusy {
		t.Fatal("uncertain runtime was reused", r)
	}
	n.wg.Wait()
}

func TestNodeProfileStopCancelsBlockedUploadAndJoinsBeforeRelease(t *testing.T) {
	_, q, reader, e, _, now := profileHolderFixture(t)
	p := collector.ProfileCapture{CaptureID: e.CaptureUID, CollectorEpoch: q.node.Epoch, ExpectationDigest: artifact.Digest{1}, DefinitionDigest: artifact.Digest{2}, AddressMode: reader.plan.AddressMode, Address: reader.plan.RouteIP, Port: reader.plan.Port, Host: "localhost", Request: execution.GoProfileRequest{Binding: e.Binding(), Pin: reader.plan.Pin, NodeUID: q.node.NodeUID, NodeBootID: q.node.BootID, SourceRef: "pprof", EndpointDigest: e.Profile.EndpointDigest, Parameters: reader.plan.Parameters, NativeLimit: 16 << 20, NotBefore: now, Deadline: now.Add(5 * time.Second)}}
	w := collector.Work{ID: e.CaptureUID, Sequence: 1, Kind: collector.WorkProfileCapture, NotAfter: now.Add(time.Second), Profile: &p}
	budget, err := collector.NewBudget(collector.Ceilings{FrozenBytes: 32 << 20, UploadBytesPerSecond: 1 << 20, UploadBurstBytes: 1 << 20}, now)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	entered, cancelled, join := make(chan struct{}), make(chan struct{}), make(chan struct{})
	parent, end := context.WithCancel(t.Context())
	defer end()
	defer close(join)
	n := &nodeProfiles{identity: func() collector.Identity { return q.node }, now: time.Now, budget: func() *collector.Budget { return budget }, budgetMu: &mu,
		acquire: func(ctx context.Context, _ collector.ProfileCapture, _ []byte, out io.Writer) (execution.GoProfileOutcome, error) {
			_, err := out.Write([]byte("native"))
			return execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: time.Now().UTC(), MayHaveStarted: true, ResponseComplete: err == nil, NativeBytes: 6}, err
		},
		upload: func(ctx context.Context, _ string, _ collector.ProfileResult, _ io.Reader) error {
			close(entered)
			<-ctx.Done()
			close(cancelled)
			<-join
			return ctx.Err()
		}}
	if r := n.start(parent, q.node.Epoch, w, nil, false); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	<-entered
	cancel := collector.Work{ID: "22222222-2222-4222-8222-222222222222", Sequence: 2, Kind: collector.WorkCancelProfileCapture, NotAfter: now.Add(time.Second), CancelProfile: &collector.PacketCancel{CaptureID: p.CaptureID, WorkID: w.ID}}
	if r := n.stop(cancel); r.Outcome != collector.OutcomeAccepted {
		t.Fatal(r)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel the exact active upload")
	}
	mu.Lock()
	held := budget.Usage(time.Now()).FrozenReserved
	mu.Unlock()
	if held != p.Request.NativeLimit {
		t.Fatal("unjoined upload released budget", held)
	}
	// Cleanup joins before the test returns; release is never inferred from Stop alone.
	t.Cleanup(func() {
		n.wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		if budget.Usage(time.Now()).FrozenReserved != 0 {
			t.Error("joined upload retained local buffer charge")
		}
	})
}
