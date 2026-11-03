package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
)

type fifoStoreBarrier struct {
	entered, release chan struct{}
	signal, unblock  sync.Once
	puts             atomic.Int32
}

func newFIFOStoreBarrier(t *testing.T) *fifoStoreBarrier {
	b := &fifoStoreBarrier{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(b.open)
	return b
}
func (b *fifoStoreBarrier) open() { b.unblock.Do(func() { close(b.release) }) }
func (b *fifoStoreBarrier) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b.signal.Do(func() { close(b.entered) })
		<-b.release
		snapshotPUT(t, w, r, b.puts.Add(1))
	}
}
func awaitFIFO(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("store barrier not reached")
	}
}
func awaitFIFOResult(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case err := <-ch:
		if err != nil {
			t.Fatal("store failed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("store did not join")
	}
}
func waitPacketStorePending(t *testing.T, h *ConnectorRecordings, id string, done <-chan error) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	end := time.After(5 * time.Second)
	for {
		h.mu.Lock()
		pending := h.held[id].storing
		h.mu.Unlock()
		if pending {
			return
		}
		select {
		case err := <-done:
			t.Fatal("packet discarded instead of waiting", err)
		case <-tick.C:
		case <-end:
			t.Fatal("packet did not claim store")
		}
	}
}

func TestMixedStoreFIFOAdmissionPreservesAcquiredUploads(t *testing.T) {
	h, q, _, e, _, now := profileHolderFixture(t)
	e = profileWriterExpectation(t, e, now)
	recorder, err := packets.NewRecorder(nil, 64<<10, now, "synthetic FIFO")
	if err != nil {
		t.Fatal(err)
	}
	frame := syntheticTCP(80, "synthetic")
	recorder.Add(frame, uint32(len(frame)), now)
	native, _, err := recorder.Close(now, 0)
	if err != nil {
		t.Fatal(err)
	}
	type packetUpload struct {
		e       artifact.ContextExpectation
		result  collector.PacketResult
		body    *profileUnreadBody
		barrier *fifoStoreBarrier
		done    chan error
	}
	var packetUploads []*packetUpload
	for i := 1; i <= 3; i++ {
		pe := e
		pe.CaptureUID = fmt.Sprintf("22222222-2222-4222-8222-%012d", i)
		pe.Registration.Location.ArtifactID = pe.CaptureUID
		pe.Registration.Location.AttemptID = pe.CaptureUID
		pe.Profile = nil
		pe.Recording = recordingExpectation(now).Recording
		pe.NativeType, pe.DataClass = artifact.PCAPNGArtifact, "metadata"
		pe.Registration.NativeLimit = artifact.RecordingNativeLimit
		b := newFIFOStoreBarrier(t)
		p := preparedSnapshot(t, pe, b.handler(t))
		h.held[pe.CaptureUID] = &heldRecording{expectation: pe, digest: evidence.ContextExpectationDigest(pe), prepared: p, nodeUID: q.node.NodeUID, workID: pe.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
		packetUploads = append(packetUploads, &packetUpload{e: pe, result: collector.PacketResult{WorkID: pe.CaptureUID, CaptureID: pe.CaptureUID, NativeType: pe.NativeType, StartedAt: now, EndedAt: now, CapturedBytes: int64(len(native)), Snaplen: artifact.RecordingSnaplen}, body: &profileUnreadBody{Reader: bytes.NewReader(native)}, barrier: b, done: make(chan error, 1)})
	}
	pb := newFIFOStoreBarrier(t)
	pp := preparedSnapshot(t, e, pb.handler(t))
	h.profiles = map[string]*heldProfile{e.CaptureUID: {expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: pp, node: q.node, workID: e.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}}
	pr, pbody := profileCapacityResult(t, e, e.CaptureUID, now)
	profileDone := make(chan error, 1)
	// All HTTP barriers must open before preparedSnapshot's listener cleanup.
	defer func() {
		pb.open()
		for _, u := range packetUploads {
			u.barrier.open()
		}
	}()
	startPacket := func(u *packetUpload) {
		go func() { u.done <- h.DeliverPacket(t.Context(), q.node, u.result, u.body) }()
	}
	startPacket(packetUploads[0])
	awaitFIFO(t, packetUploads[0].barrier.entered)
	startPacket(packetUploads[1])
	awaitFIFO(t, packetUploads[1].barrier.entered)
	go func() { profileDone <- h.DeliverProfile(t.Context(), q.node, pr, pbody) }()
	waitProfileStorePending(t, h, e.CaptureUID, profileDone)
	later := packetUploads[2]
	startPacket(later)
	waitPacketStorePending(t, h, later.e.CaptureUID, later.done)
	h.mu.Lock()
	storing := h.storing
	h.mu.Unlock()
	if storing != 2*int64(len(native)) || pbody.reads.Load() != 0 || later.body.reads.Load() != 0 {
		t.Fatalf("new packet overtook waiting profile: reserved=%d want=%d profileReads=%d packetReads=%d", storing, 2*len(native), pbody.reads.Load(), later.body.reads.Load())
	}
	if err := h.DeliverPacket(t.Context(), q.node, later.result, bytes.NewReader(nil)); err == nil {
		t.Fatal("queued packet delivery replay")
	}
	packetUploads[0].barrier.open()
	awaitFIFOResult(t, packetUploads[0].done)
	if pbody.reads.Load() != 0 || later.body.reads.Load() != 0 {
		t.Fatal("body consumed before FIFO head fits")
	}
	packetUploads[1].barrier.open()
	awaitFIFOResult(t, packetUploads[1].done)
	awaitFIFO(t, pb.entered)
	if later.body.reads.Load() != 0 {
		t.Fatal("packet bypassed active profile")
	}
	pb.open()
	awaitFIFOResult(t, profileDone)
	awaitFIFO(t, later.barrier.entered)
	later.barrier.open()
	awaitFIFOResult(t, later.done)
	for _, u := range packetUploads {
		out, err := h.Collect(fleet.APIContextWork{CaptureID: u.e.CaptureUID, AttemptID: u.e.Registration.Location.AttemptID, ExpectationDigest: evidence.ContextExpectationDigest(u.e)})
		if err != nil || out.State != evidence.RecordingStored || u.barrier.puts.Load() != 4 {
			t.Fatal("packet result lost", out, err, u.barrier.puts.Load())
		}
	}
	out, err := h.Collect(fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: pr.ExpectationDigest})
	if err != nil || out.State != evidence.RecordingStored || pb.puts.Load() != 4 || h.storing != 0 {
		t.Fatal("profile result/capacity", out, err, pb.puts.Load(), h.storing)
	}
}

// Cancelling one retained profile must not remove another owner or refund an
// unrelated storage reservation.
func TestStoreFIFOCancelRemovesOwnWaiter(t *testing.T) {
	h, q, _, e, _, now := profileHolderFixture(t)
	e = profileWriterExpectation(t, e, now)
	var profilePuts atomic.Int32
	pp := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, profilePuts.Add(1)) }))
	h.storing = 17
	h.profiles = map[string]*heldProfile{e.CaptureUID: {expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: pp, node: q.node, workID: e.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}}
	pr, pbody := profileCapacityResult(t, e, e.CaptureUID, now)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.DeliverProfile(ctx, q.node, pr, pbody) }()
	waitProfileStorePending(t, h, e.CaptureUID, done)
	// A second profile waits too. Its cancellation cannot remove the first owner.
	second := e
	second.CaptureUID = "22222222-2222-4222-8222-222222222222"
	second.Registration.Location.ArtifactID = second.CaptureUID
	second.Registration.Location.AttemptID = second.CaptureUID
	sp := preparedSnapshot(t, second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("cancelled queued profile reached backend") }))
	h.mu.Lock()
	h.profiles[second.CaptureUID] = &heldProfile{expectation: second, digest: evidence.ContextExpectationDigest(second), prepared: sp, node: q.node, workID: second.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
	h.mu.Unlock()
	sr, sbody := profileCapacityResult(t, second, second.CaptureUID, now)
	sctx, scancel := context.WithCancel(t.Context())
	defer scancel()
	sdone := make(chan error, 1)
	go func() { sdone <- h.DeliverProfile(sctx, q.node, sr, sbody) }()
	waitProfileStorePending(t, h, second.CaptureUID, sdone)
	scancel()
	select {
	case err := <-sdone:
		if err == nil {
			t.Fatal("cancelled profile success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not join")
	}
	if pbody.reads.Load() != 0 || sbody.reads.Load() != 0 || h.storing != 17 {
		t.Fatal("cancellation changed another waiter or reservation")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled profile success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("head cancel did not join")
	}
	if profilePuts.Load() != 0 || h.storing != 17 {
		t.Fatal("cancelled queue refunded occupied storage")
	}
}

func TestWaitingPacketHonorsParentCancellationAndWriteUntil(t *testing.T) {
	for _, ending := range []string{"caller", "write-end"} {
		t.Run(ending, func(t *testing.T) {
			h, q, _, e, _, now := profileHolderFixture(t)
			e = profileWriterExpectation(t, e, now)
			e.Profile = nil
			e.Recording = recordingExpectation(now).Recording
			e.NativeType, e.DataClass = artifact.PCAPNGArtifact, "metadata"
			e.Registration.NativeLimit = artifact.RecordingNativeLimit
			if ending == "write-end" {
				e.Registration.WriteUntil = time.Now().Add(500 * time.Millisecond).UTC().Truncate(time.Microsecond)
			}
			var puts atomic.Int32
			p := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
			recorder, err := packets.NewRecorder(nil, 64<<10, now, "synthetic queued cancellation")
			if err != nil {
				t.Fatal(err)
			}
			frame := syntheticTCP(80, "synthetic")
			recorder.Add(frame, uint32(len(frame)), now)
			native, _, err := recorder.Close(now, 0)
			if err != nil {
				t.Fatal(err)
			}
			h.storing = maxStoringBytes
			h.held[e.CaptureUID] = &heldRecording{expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: p, nodeUID: q.node.NodeUID, workID: e.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
			result := collector.PacketResult{WorkID: e.CaptureUID, CaptureID: e.CaptureUID, NativeType: e.NativeType, StartedAt: now, EndedAt: now, CapturedBytes: int64(len(native)), Snaplen: artifact.RecordingSnaplen}
			body := &profileUnreadBody{Reader: bytes.NewReader(native)}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.DeliverPacket(ctx, q.node, result, body) }()
			waitPacketStorePending(t, h, e.CaptureUID, done)
			if ending == "caller" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled packet store succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("packet wait did not join")
			}
			h.mu.Lock()
			held := h.held[e.CaptureUID]
			correct := held.prepared == nil && !held.storing && held.outcome.State == evidence.RecordingFailed && h.storing == maxStoringBytes && len(h.storeWaiters) == 0
			h.mu.Unlock()
			if !correct || body.reads.Load() != 0 || puts.Load() != 0 {
				t.Fatal("cancelled/expired packet changed storage or read body")
			}
			if err := h.DeliverPacket(t.Context(), q.node, result, bytes.NewReader(nil)); err == nil {
				t.Fatal("cancelled packet replay")
			}
		})
	}
}

func TestStoreFIFOCancelledHeadWakesFittingSuccessor(t *testing.T) {
	h := NewConnectorRecordings(nil, nil, time.Now, func(string) {})
	h.storing = 17
	until := time.Now().Add(time.Minute)
	run := func(ctx context.Context, bytes int64) <-chan bool {
		done := make(chan bool, 1)
		go func() { h.mu.Lock(); ok := h.waitStoreLocked(ctx, until, bytes); h.mu.Unlock(); done <- ok }()
		return done
	}
	waitCount := func(want int) {
		t.Helper()
		end := time.After(5 * time.Second)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			h.mu.Lock()
			n := len(h.storeWaiters)
			h.mu.Unlock()
			if n == want {
				return
			}
			select {
			case <-tick.C:
			case <-end:
				t.Fatal("FIFO count", n, want)
			}
		}
	}
	headCtx, cancelHead := context.WithCancel(t.Context())
	defer cancelHead()
	head := run(headCtx, maxStoringBytes)
	waitCount(1)
	next := run(t.Context(), 1)
	waitCount(2)
	tailCtx, cancelTail := context.WithCancel(t.Context())
	defer cancelTail()
	tail := run(tailCtx, 1)
	waitCount(3)
	cancelTail()
	if <-tail {
		t.Fatal("cancelled tail admitted")
	}
	waitCount(2)
	cancelHead()
	if <-head {
		t.Fatal("cancelled head admitted")
	}
	select {
	case ok := <-next:
		if !ok {
			t.Fatal("fitting successor refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not notify successor")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.storeWaiters) != 0 || h.storing != 18 {
		t.Fatal("wrong queue/reservation", len(h.storeWaiters), h.storing)
	}
	h.releaseStoreLocked(1)
	if h.storing != 17 {
		t.Fatal("refunded unrelated capacity")
	}
}
