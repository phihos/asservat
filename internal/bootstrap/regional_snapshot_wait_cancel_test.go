package bootstrap

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
)

type snapshotWaitCancelQueue struct {
	snapshotCancelQueue
	cancelClient context.CancelFunc
}

func (q *snapshotWaitCancelQueue) EnqueueSourceSnapshotCancel(ctx context.Context, x collector.SourceSnapshot, until time.Time) (collector.Work, error) {
	work, err := q.snapshotCancelQueue.EnqueueSourceSnapshotCancel(ctx, x, until)
	if err == nil && q.cancelClient != nil {
		q.cancelClient()
	}
	return work, err
}

// The node upload is actual HTTP/1 TLS. Its body remains unread while a real
// profile writer owns capacity; closing the client is not a server-side Stop
// observation until HTTP performs I/O. The explicit local wait hook must work
// independently, without substituting queue acknowledgement for a node receipt.
func TestRegionalSnapshotCancellationStopsUnreadFIFOOwner(t *testing.T) {
	for _, when := range []string{"waiting", "before-upload"} {
		t.Run(when, func(t *testing.T) {
			var holder *ConnectorRecordings
			resultReady := make(chan collector.PacketResult, 1)
			uploadCancel := make(chan context.CancelFunc, 1)
			serverReady := make(chan context.CancelFunc, 1)
			delivered := make(chan error, 1)
			var unread atomic.Int64
			var node collector.Identity
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 1 {
					t.Error("fixture must exercise HTTP/1")
				}
				result := <-resultReady
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				serverReady <- cancel
				err := holder.DeliverPacket(ctx, node, result, snapshotUnreadHTTPBody{Reader: r.Body, reads: &unread})
				delivered <- err
				if err != nil {
					w.WriteHeader(http.StatusConflict)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client := server.Client()
			n, _, clock, x := sourceSnapshotPipelineFixture(t, func(ctx context.Context, _ string, r collector.PacketResult, native []byte) error {
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				uploadCancel <- cancel
				resultReady <- r
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, bytes.NewReader(native))
				if err != nil {
					return err
				}
				response, err := client.Do(req)
				if response != nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
					if response.StatusCode != http.StatusNoContent {
						err = artifact.ErrInvalid
					}
				}
				return err
			})
			node = collector.Identity{NodeUID: x.Binding.NodeUID, BootID: x.Binding.BootID, PodUID: x.Binding.CollectorPodUID, Epoch: x.Binding.CollectorEpoch}
			x = distinctCancellationSnapshot(x)
			expected := snapshotExpected(t, x)
			x.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(expected))
			nodes := &snapshotWaitCancelQueue{}
			holder = NewConnectorRecordings(nodes, nil, clock.now, func(string) {})
			_, pq, _, pe, _, pn := profileHolderFixture(t)
			pe = profileWriterExpectation(t, pe, pn)
			pe.CaptureUID = "88888888-8888-4888-8888-888888888888"
			pe.Registration.Location.ArtifactID = pe.CaptureUID
			pe.Registration.Location.AttemptID = pe.CaptureUID
			barrier := newFIFOStoreBarrier(t)
			profile := preparedSnapshot(t, pe, barrier.handler(t))
			holder.profiles = map[string]*heldProfile{pe.CaptureUID: {expectation: pe, digest: evidence.ContextExpectationDigest(pe), prepared: profile, node: pq.node, workID: pe.CaptureUID, queued: pn, expires: pn.Add(2 * time.Minute), outcome: evidence.RecordingCollection{State: evidence.RecordingPending}}}
			pr, pbody := profileCapacityResult(t, pe, pe.CaptureUID, pn)
			profileDone := make(chan error, 1)
			defer barrier.open()
			go func() { profileDone <- holder.DeliverProfile(t.Context(), pq.node, pr, pbody) }()
			awaitFIFO(t, barrier.entered)
			var puts atomic.Int32
			prepared := preparedSnapshot(t, expected, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { snapshotPUT(t, w, r, puts.Add(1)) }))
			output := holder.Prepare(prepared, expected)
			ctx, cancel := context.WithDeadline(t.Context(), x.Request.StartBy)
			defer cancel()
			if _, err := output.StartSourceSnapshot(ctx, x); err != nil {
				t.Fatal(err)
			}
			if when == "before-upload" {
				if err := holder.CancelSourceSnapshot(ctx, x); err != nil {
					t.Fatal(err)
				}
			}
			work := collector.Work{ID: x.Request.SnapshotID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: x.Request.StartBy, Snapshot: &x}
			if result := n.decide(t.Context(), x.Binding.CollectorEpoch, work); result.Outcome != collector.OutcomeAccepted {
				t.Fatal(result)
			}
			cleanupHandler := <-serverReady
			defer cleanupHandler()
			nodes.cancelClient = <-uploadCancel
			if when == "waiting" {
				waitPacketStorePending(t, holder, x.CaptureID, delivered)
				if unread.Load() != 0 {
					t.Fatal("queued snapshot body read")
				}
				if err := holder.CancelSourceSnapshot(ctx, x); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-delivered:
				if err == nil {
					t.Fatal("cancelled snapshot store succeeded")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("snapshot cancellation did not join unread FIFO wait")
			}
			if unread.Load() != 0 || puts.Load() != 0 {
				t.Fatal("cancelled queued body reached storage")
			}
			holder.mu.Lock()
			reserved := holder.storing
			waiters := len(holder.storeWaiters)
			storing := holder.held[x.CaptureID].storing
			holder.mu.Unlock()
			if reserved != maxStoringBytes || waiters != 0 || storing {
				t.Fatal("cancellation released profile reservation or kept local owner", reserved, waiters, storing)
			}
			if out, err := holder.Collect(snapshotCollect(x)); err != nil || out.State != evidence.RecordingPending {
				t.Fatal("queue/local join fabricated node receipt", out, err)
			}
			n.snapshotWG.Wait()
			nodes.joinedAt = clock.now()
			if out, err := holder.Collect(snapshotCollect(x)); err != nil || out.State != evidence.RecordingCancelled || out.SnapshotCancellation == nil || !out.SnapshotCancellation.Request.Equal(x.Request) {
				t.Fatal("joined cancellation missing original scope", out, err)
			}
			barrier.open()
			awaitFIFOResult(t, profileDone)
			holder.mu.Lock()
			reserved = holder.storing
			holder.mu.Unlock()
			if puts.Load() != 0 || unread.Load() != 0 || reserved != 0 || barrier.puts.Load() != 4 {
				t.Fatal("later capacity release revived cancelled writer")
			}
			assertSourceBudget(t, n, 0, 1)
		})
	}
}

type snapshotUnreadHTTPBody struct {
	io.Reader
	reads *atomic.Int64
}

func (r snapshotUnreadHTTPBody) Read(b []byte) (int, error) { r.reads.Add(1); return r.Reader.Read(b) }
