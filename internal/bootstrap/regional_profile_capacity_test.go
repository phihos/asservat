package bootstrap

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"github.com/google/pprof/profile"
)

type profileUnreadBody struct {
	io.Reader
	reads atomic.Int64
}

func (b *profileUnreadBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.Reader.Read(p)
}

func profileCapacityResult(t *testing.T, e artifact.ContextExpectation, workID string, now time.Time) (collector.ProfileResult, *profileUnreadBody) {
	t.Helper()
	var native bytes.Buffer
	sample := &profile.Profile{SampleType: []*profile.ValueType{{Type: "alloc_objects", Unit: "count"}}, Sample: []*profile.Sample{{Value: []int64{1}}}}
	if err := sample.Write(&native); err != nil {
		t.Fatal(err)
	}
	return collector.ProfileResult{WorkID: workID, CaptureID: e.CaptureUID, ExpectationDigest: evidence.ContextExpectationDigest(e), EndpointDigest: e.Profile.EndpointDigest, Outcome: execution.GoProfileOutcome{Format: artifact.PprofFormat, StartedAt: now, CompletedAt: now, MayHaveStarted: true, ResponseComplete: true, NativeBytes: int64(native.Len())}}, &profileUnreadBody{Reader: bytes.NewReader(native.Bytes())}
}

func waitProfileStorePending(t *testing.T, h *ConnectorRecordings, capture string, done <-chan error) {
	t.Helper()
	until := time.After(5 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		h.mu.Lock()
		pending := h.profiles[capture].storing
		h.mu.Unlock()
		if pending {
			return
		}
		select {
		case err := <-done:
			t.Fatal("completed acquisition discarded instead of waiting for storage capacity", err)
		case <-until:
			t.Fatal("profile did not enter bounded store wait")
		case <-tick.C:
		}
	}
}

func TestProfileWaitsForSharedStoreAndStoresOnce(t *testing.T) {
	for _, blocker := range []string{"packet", "profile"} {
		t.Run(blocker, func(t *testing.T) {
			h, q, reader, e, endpoint, now := profileHolderFixture(t)
			e = profileWriterExpectation(t, e, now)
			reader.plan.NativeLimit, endpoint.NativeLimit = e.Profile.MaxBytes, e.Profile.MaxBytes
			entered, release := make(chan struct{}), make(chan struct{})
			var signal, unblock sync.Once
			defer unblock.Do(func() { close(release) })
			var firstPuts, profilePuts atomic.Int32
			first := e
			first.CaptureUID = "22222222-2222-4222-8222-222222222222"
			first.Registration.Location.ArtifactID = first.CaptureUID
			first.Registration.Location.AttemptID = first.CaptureUID
			if blocker == "packet" {
				first.Profile = nil
				first.Recording = recordingExpectation(now).Recording
				first.NativeType, first.DataClass = artifact.PCAPNGArtifact, "metadata"
				first.Registration.NativeLimit = artifact.RecordingNativeLimit
			}
			prepared := preparedSnapshot(t, first, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				signal.Do(func() { close(entered) })
				<-release
				snapshotPUT(t, w, r, firstPuts.Add(1))
			}))
			firstDone := make(chan error, 1)
			if blocker == "packet" {
				recorder, err := packets.NewRecorder(nil, 64<<10, now, "synthetic capacity blocker")
				if err != nil {
					t.Fatal(err)
				}
				frame := syntheticTCP(80, "synthetic")
				recorder.Add(frame, uint32(len(frame)), now)
				native, _, err := recorder.Close(now, 0)
				if err != nil {
					t.Fatal(err)
				}
				h.held[first.CaptureUID] = &heldRecording{expectation: first, digest: evidence.ContextExpectationDigest(first), prepared: prepared, nodeUID: q.node.NodeUID, workID: first.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}
				r := collector.PacketResult{WorkID: first.CaptureUID, CaptureID: first.CaptureUID, NativeType: first.NativeType, StartedAt: now, EndedAt: now, CapturedBytes: int64(len(native)), Snaplen: artifact.RecordingSnaplen}
				go func() { firstDone <- h.DeliverPacket(t.Context(), q.node, r, bytes.NewReader(native)) }()
			} else {
				h.profiles = map[string]*heldProfile{first.CaptureUID: {expectation: first, digest: evidence.ContextExpectationDigest(first), prepared: prepared, node: q.node, workID: first.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}}
				r, body := profileCapacityResult(t, first, first.CaptureUID, now)
				go func() { firstDone <- h.DeliverProfile(t.Context(), q.node, r, body) }()
			}
			select {
			case <-entered:
			case err := <-firstDone:
				t.Fatal("blocker never reached storage", err)
			case <-time.After(5 * time.Second):
				t.Fatal("blocker never reached storage")
			}
			second := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, profilePuts.Add(1)) }))
			if _, err := h.PrepareProfile(second, e).StartProfile(t.Context(), reader.plan.Pin, now, now.Add(time.Second), endpoint); err != nil {
				t.Fatal(err)
			}
			r, body := profileCapacityResult(t, e, q.profiles[0].ID, now)
			done := make(chan error, 1)
			go func() { done <- h.DeliverProfile(t.Context(), q.node, r, body) }()
			waitProfileStorePending(t, h, e.CaptureUID, done)
			if body.reads.Load() != 0 || profilePuts.Load() != 0 {
				t.Fatal("waiting profile consumed body or contacted storage")
			}
			// The result is one-use even while the original waits for capacity.
			if err := h.DeliverProfile(t.Context(), q.node, r, body); err == nil {
				t.Fatal("duplicate delivery inherited queued store")
			}
			unblock.Do(func() { close(release) })
			for _, completed := range []<-chan error{firstDone, done} {
				select {
				case err := <-completed:
					if err != nil {
						t.Fatal("store did not resume after capacity release", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("capacity release did not wake profile")
				}
			}
			out, err := h.Collect(fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: r.ExpectationDigest})
			if err != nil || out.State != evidence.RecordingStored || firstPuts.Load() != 4 || profilePuts.Load() != 4 || h.storing != 0 {
				t.Fatal("one-shot storage/capacity outcome", out, firstPuts.Load(), profilePuts.Load(), h.storing, err)
			}
		})
	}
}

func TestProfileCapacityWaitHonorsStopCancellationAndOriginalWriteEnd(t *testing.T) {
	for _, end := range []string{"stop", "caller", "write-end"} {
		t.Run(end, func(t *testing.T) {
			h, q, _, e, _, now := profileHolderFixture(t)
			e = profileWriterExpectation(t, e, now)
			if end == "write-end" {
				e.Registration.WriteUntil = time.Now().Add(500 * time.Millisecond).UTC().Truncate(time.Microsecond)
			}
			var puts atomic.Int32
			prepared := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
			// Synthetic occupied capacity; this subtest must never acquire or refund it.
			h.storing = 17
			h.profiles = map[string]*heldProfile{e.CaptureUID: {expectation: e, digest: evidence.ContextExpectationDigest(e), prepared: prepared, node: q.node, workID: e.CaptureUID, queued: now, expires: now.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}}
			r, body := profileCapacityResult(t, e, e.CaptureUID, now)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- h.DeliverProfile(ctx, q.node, r, body) }()
			waitProfileStorePending(t, h, e.CaptureUID, done)
			if end == "stop" {
				stop := collector.ProfileStop{RootID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, WriterPodUID: e.CaptureUID, WriterEpoch: e.CaptureUID, ExpectationDigest: r.ExpectationDigest, WriteUntil: e.Registration.WriteUntil}
				if err := h.CancelProfile(t.Context(), stop); err != nil {
					t.Fatal(err)
				}
			} else if end == "caller" {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled wait reported success")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("store wait did not join within its original end")
			}
			out, err := h.Collect(fleet.APIContextWork{CaptureID: e.CaptureUID, AttemptID: e.Registration.Location.AttemptID, ExpectationDigest: r.ExpectationDigest})
			want := evidence.RecordingFailed
			if end == "stop" {
				want = evidence.RecordingCancelled
				if out.ProfileCancellation == nil || !out.ProfileCancellation.MayHaveStarted {
					t.Fatal("acquired result lost application uncertainty", out)
				}
			}
			if err != nil || out.State != want || h.storing != 17 || puts.Load() != 0 || body.reads.Load() != 0 || h.profiles[e.CaptureUID].storing {
				t.Fatal("cancelled wait changed storage or read body", out, err, h.storing, puts.Load(), body.reads.Load())
			}
		})
	}
}
