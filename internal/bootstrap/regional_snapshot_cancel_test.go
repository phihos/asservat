package bootstrap

import (
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type snapshotCancelQueue struct {
	snapshotRecordingQueue
	cancelled *collector.SourceSnapshot
	cancelID  string
	joinedAt  time.Time // synthetic accepted exact node receipt; queue success alone stays unknown
}

func (q *snapshotCancelQueue) EnqueueSourceSnapshotCancel(_ context.Context, x collector.SourceSnapshot, _ time.Time) (collector.Work, error) {
	q.cancelled = &x
	q.cancelID = "22222222-2222-4222-8222-222222222222"
	return collector.Work{ID: q.cancelID, Sequence: 2}, nil
}
func (q *snapshotCancelQueue) SourceSnapshotCancellation(x collector.SourceSnapshot, id string) (time.Time, bool) {
	return q.joinedAt, q.cancelled != nil && q.cancelled.Equal(x) && id == q.cancelID && !q.joinedAt.IsZero()
}
func snapshotCollect(x collector.SourceSnapshot) fleet.APIContextWork {
	return fleet.APIContextWork{CaptureID: x.CaptureID, AttemptID: x.AttemptID, ExpectationDigest: artifact.Digest(x.ExpectationDigest)}
}

func TestRegionalSnapshotCancelBeforeStartDoesNotTransferPreparedKeys(t *testing.T) {
	n, _, clock, x := sourceSnapshotPipelineFixture(t, nil)
	x = distinctCancellationSnapshot(x)
	e := snapshotExpected(t, x)
	x.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
	nodes := &snapshotCancelQueue{}
	h := NewConnectorRecordings(nodes, nil, clock.now, func(string) {})
	output := h.Prepare(&objectstore.PreparedArtifact{}, e)
	defer output.Close()
	ctx, cancel := context.WithDeadline(t.Context(), x.Request.StartBy)
	defer cancel()
	if err := h.CancelSourceSnapshot(ctx, x); err != nil {
		t.Fatal(err)
	}
	if _, err := output.StartSourceSnapshot(ctx, x); err == nil || output.prepared == nil || len(nodes.got) != 0 {
		t.Fatal("delayed start transferred cancelled prepared output", err)
	}
	if c, err := h.Collect(snapshotCollect(x)); err != nil || c.State != evidence.RecordingPending {
		t.Fatal("queue acknowledgement was mistaken for joined cancellation", c, err)
	}
	other := x
	other.AttemptID = "33333333-3333-4333-8333-333333333333"
	if err := h.CancelSourceSnapshot(ctx, other); err == nil {
		t.Fatal("another attempt cancelled original holder")
	}
	nodes.joinedAt = clock.now()
	if c, err := h.Collect(snapshotCollect(x)); err != nil || c.State != evidence.RecordingCancelled || c.SnapshotCancellation == nil || !c.SnapshotCancellation.Request.Equal(x.Request) {
		t.Fatal(c, err)
	}
	assertSourceBudget(t, n, 0, 1)
}

func TestRegionalSnapshotCancellationWaitsForRealWriterAndStoredWins(t *testing.T) {
	for _, tc := range []struct {
		name            string
		stored, expired bool
	}{{"failedWriter", false, false}, {"storedWins", true, false}, {"expiredNoncooperativeWriter", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			stored := tc.stored
			var holder *ConnectorRecordings
			var source *packetSource
			delivered := make(chan error, 1)
			n, actualSource, clock, x := sourceSnapshotPipelineFixture(t, func(ctx context.Context, _ string, r collector.PacketResult, native []byte) error {
				b := source.meter.Permit().Binding
				err := holder.DeliverPacket(ctx, collector.Identity{NodeUID: b.NodeUID, BootID: b.BootID, PodUID: b.CollectorPodUID, Epoch: b.CollectorEpoch}, r, bytes.NewReader(native))
				delivered <- err
				return err
			})
			source = actualSource
			x = distinctCancellationSnapshot(x)
			e := snapshotExpected(t, x)
			x.ExpectationDigest = [32]byte(evidence.ContextExpectationDigest(e))
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			var puts atomic.Int32
			prepared := preparedSnapshot(t, e, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := puts.Add(1)
				if count == 1 {
					close(entered)
					<-release
					if !stored {
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					}
				}
				snapshotPUT(t, w, r, count)
			}))
			nodes := &snapshotCancelQueue{}
			holder = NewConnectorRecordings(nodes, nil, clock.now, func(string) {})
			output := holder.Prepare(prepared, e)
			ctx, cancel := context.WithDeadline(t.Context(), x.Request.StartBy)
			defer cancel()
			if _, err := output.StartSourceSnapshot(ctx, x); err != nil {
				t.Fatal(err)
			}
			work := collector.Work{ID: x.Request.SnapshotID, Sequence: 1, Kind: collector.WorkPacketSourceSnapshot, NotAfter: x.Request.StartBy, Snapshot: &x}
			if r := n.decide(t.Context(), x.Binding.CollectorEpoch, work); r.Outcome != collector.OutcomeAccepted {
				t.Fatal(r)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("real encrypted producer never reached PUT")
			}
			if err := holder.CancelSourceSnapshot(ctx, x); err != nil {
				t.Fatal(err)
			}
			if c, err := holder.Collect(snapshotCollect(x)); err != nil || c.State != evidence.RecordingPending {
				t.Fatal("queued cancel claimed terminal state", c, err)
			}
			nodes.joinedAt = clock.now()
			// A node receipt does not certify the independent regional Store call joined.
			if c, err := holder.Collect(snapshotCollect(x)); err != nil || c.State != evidence.RecordingPending {
				t.Fatal("node join forgot in-flight regional writer", c, err)
			}
			if tc.expired {
				holder.mu.Lock()
				expiry := holder.held[x.CaptureID].expires
				holder.mu.Unlock()
				clock.set(expiry)
				if c, err := holder.Collect(snapshotCollect(x)); err != nil || c.State != evidence.RecordingPending {
					t.Fatal("expiry forgot in-flight regional writer", c, err)
				}
			}
			close(release)
			select {
			case err := <-delivered:
				if stored && err != nil || !stored && err == nil {
					t.Fatal("unexpected writer result", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not join")
			}
			c, err := holder.Collect(snapshotCollect(x))
			if tc.expired {
				if err == nil {
					t.Fatal("expired noncooperative writer invented terminal cancellation", c)
				}
				n.snapshotWG.Wait()
				assertSourceBudget(t, n, 0, 1)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stored {
				if c.State != evidence.RecordingStored || c.SnapshotCancellation != nil || puts.Load() != 4 {
					t.Fatal("cancel erased a stored artifact", c, puts.Load())
				}
			} else if c.State != evidence.RecordingCancelled || c.SnapshotCancellation == nil {
				t.Fatal("joined failed writer did not cancel", c)
			}
			n.snapshotWG.Wait()
			assertSourceBudget(t, n, 0, 1)
		})
	}
}
