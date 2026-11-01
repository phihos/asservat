package contextstart

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"context"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type sourceWorkVerifierFunc func(context.Context, []byte, fleet.APIContextReceiver) (app.AuthenticatedSourceWork, error)

func (f sourceWorkVerifierFunc) VerifySourceWork(ctx context.Context, b []byte, r fleet.APIContextReceiver) (app.AuthenticatedSourceWork, error) {
	return f(ctx, b, r)
}

type sourceQueue struct {
	calls int
	last  collector.SourcePermit
	fail  bool
}

func (q *sourceQueue) EnqueueSourceExpected(ctx context.Context, n targets.PacketSourceObservation, s collector.PacketSource) (collector.Work, error) {
	q.calls++
	q.last = s.Permit
	if ctx.Err() != nil || q.fail {
		return collector.Work{}, fleet.ErrUnavailable
	}
	return collector.Work{Kind: collector.WorkPacketSource, Source: &s}, nil
}
func (q *sourceQueue) EnqueueSourceStop(ctx context.Context, b collector.SourceBinding, end time.Time) (collector.Work, error) {
	q.calls++
	if ctx.Err() != nil || q.fail {
		return collector.Work{}, fleet.ErrUnavailable
	}
	return collector.Work{Kind: collector.WorkStopPacketSource, StopSource: &b, NotAfter: end}, nil
}

func sourceStreamWorkFixture() (app.SourceWork, fleet.APIContextReceiver) {
	a := workFixture()
	base := a.Work
	now := base.IssuedAt
	id := base.CaptureID
	resources := collector.SourceResources{PolicyUID: "budget"}
	p := collector.SourcePermit{Binding: collector.SourceBinding{RootID: base.Channel.RootID, PolicyUID: "policy", AcceptanceID: base.AttemptID, SourceID: id, Fence: id, ActionID: "packets", PodUID: base.Target.PodUID, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: deliveryapp.SourceResourcesDigest(resources)}, StartedAt: now, HardUntil: now.Add(time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1 << 20, BytesPerSecond: 1 << 20}
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: base.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: base.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: base.Target.WorkloadUID}, PodName: "app-0", PodUID: base.Target.PodUID}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: base.Target.NamespaceUID, Name: "app-0", UID: base.Target.PodUID, ControllerUID: id}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	w := app.SourceWork{Channel: base.Channel, Target: target, Node: targets.PacketSourceObservation{PodUID: p.Binding.PodUID, NodeUID: p.Binding.NodeUID, BootID: p.Binding.BootID, CollectorPodUID: p.Binding.CollectorPodUID, CollectorEpoch: p.Binding.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Source: collector.PacketSource{Permit: p, Resources: resources, Ring: collector.SourceRingLimits{MaxAge: time.Minute, MaxBytes: 1024, SegmentBytes: 256, MaxSegments: 4, MaxFrozenBytes: 1024, MaxConcurrentSnapshots: 2}}, NotAfter: now.Add(3 * time.Second)}
	return w, fleet.APIContextReceiver{Channel: base.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
}

type sourceSnapshotCanceller struct {
	calls int
	last  collector.SourceSnapshot
	fail  bool
}

func (c *sourceSnapshotCanceller) CancelSourceSnapshot(ctx context.Context, x collector.SourceSnapshot) error {
	c.calls++
	c.last = x
	if ctx.Err() != nil || c.fail {
		return fleet.ErrUnavailable
	}
	return nil
}

type freshConnectorSource struct{ countingLocal }

func (freshConnectorSource) ReadConnectorIdentitySource(context.Context) (fleet.ConnectorIdentitySource, error) {
	now := time.Now()
	return fleet.ConnectorIdentitySource{Observation: fleet.ConnectorCredentialObservation{ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}}, nil
}

// Synthetic admitted authority/queue over actual hub/region frame streams and
// the real router. Real signature purpose/key checks have their JOSE test.
// Every source delivery is one query: the standby stays idle for a Save.
func TestSourceWorkIsAQueryThatKeepsTheStandby(t *testing.T) {
	for _, mode := range []string{"arm", "stop", "queue-refusal", "cancel", "cancel-refused", "sign-failure"} {
		t.Run(mode, func(t *testing.T) {
			w, r := sourceStreamWorkFixture()
			switch mode {
			case "stop":
				w = app.SourceWork{Channel: w.Channel, Source: collector.PacketSource{Permit: collector.SourcePermit{Binding: w.Source.Permit.Binding}}, Stop: true, StopIssuedAt: w.Source.Permit.IssuedAt, NotAfter: w.NotAfter}
			case "cancel", "cancel-refused":
				now := w.IssuedAt()
				b := w.Binding()
				b.AudienceDigest = [32]byte{7}
				q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(b)), SourceID: b.SourceID, Fence: b.Fence, SnapshotID: "66666666-6666-4666-8666-666666666666", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(-time.Second), T0: now.Add(-30 * time.Second), IssuedAt: now.Add(-30 * time.Second), StartBy: now.Add(-25 * time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
				x := collector.SourceSnapshot{Binding: b, CaptureID: "44444444-4444-4444-8444-444444444444", AttemptID: "55555555-5555-4555-8555-555555555555", WriterPodUID: w.Channel.Executor.PodUID, WriterEpoch: w.Channel.Executor.ProcessEpoch, ExpectationDigest: [32]byte{5}, Request: q}
				w = app.SourceWork{Channel: w.Channel, StopSnapshot: &x, StopIssuedAt: now, NotAfter: w.NotAfter}
			}
			if !w.Valid(time.Now()) {
				t.Fatal("invalid synthetic source work")
			}
			// The standby's passive residency outlives the work's own bound.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			hub, region := historyStreamPair(t, ctx, r)
			hub.sources = NewSourceFeed(r.Channel.ExchangeID, time.Now)
			region.local = freshConnectorSource{}
			region.targets = &countingLocal{}
			queue := &sourceQueue{fail: mode == "queue-refusal"}
			snapshots := &sourceSnapshotCanceller{fail: mode == "cancel-refused"}
			region.sourceWork = &SourceLocal{Queue: queue, Snapshots: snapshots, Verifier: sourceWorkVerifierFunc(func(_ context.Context, b []byte, current fleet.APIContextReceiver) (app.AuthenticatedSourceWork, error) {
				if current.Channel != w.Channel || string(b) != "synthetic-source-signature" {
					return app.AuthenticatedSourceWork{}, fleet.ErrDenied
				}
				return app.AuthenticatedSourceWork{Work: w, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: w.IssuedAt(), ValidUntil: w.NotAfter}, nil
			})}
			cluster := r.Channel.Connector.Binding.ClusterID
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			check := func(context.Context) (fleet.APIContextReceiver, error) { return r, nil }
			standby, err := router.RegisterStandby(ctx, r, check)
			if err != nil {
				t.Fatal(err)
			}
			served := make(chan struct{})
			go func() { defer close(served); defer standby.Finish(); _ = standby.Serve(hub, time.Now) }()
			regionDone := make(chan struct{})
			go func() { defer close(regionDone); _, _, _ = region.AwaitWork(ctx) }()
			defer func() { cancel(); _ = hub.Close(); _ = region.Close(); <-served; <-regionDone }()

			call, end := context.WithTimeout(ctx, time.Second)
			defer end()
			err = router.DeliverSource(call, cluster, func(current fleet.APIContextReceiver) (app.SourceWork, []byte, error) {
				if current.Channel != r.Channel {
					t.Error("work signed for another channel")
				}
				if mode == "sign-failure" {
					return w, nil, fleet.ErrDenied
				}
				return w, []byte("synthetic-source-signature"), nil
			})
			switch mode {
			case "queue-refusal", "cancel-refused":
				if !errors.Is(err, fleet.ErrUnavailable) {
					t.Fatal("effect refusal lost", err)
				}
			case "sign-failure":
				if !errors.Is(err, fleet.ErrDenied) {
					t.Fatal("sign failure lost", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			cancelling := mode == "cancel" || mode == "cancel-refused"
			switch {
			case mode == "sign-failure":
				if queue.calls != 0 || snapshots.calls != 0 {
					t.Fatal("unsigned work reached the region")
				}
			case cancelling:
				if snapshots.calls != 1 || !snapshots.last.Equal(*w.StopSnapshot) || queue.calls != 0 {
					t.Fatal("cancellation became source arm/stop or replayed", snapshots.calls, queue.calls)
				}
			default:
				if queue.calls != 1 || snapshots.calls != 0 {
					t.Fatal("uncertain enqueue replayed", queue.calls)
				}
				if mode == "arm" && queue.last != w.Source.Permit {
					t.Fatal("original source grant changed")
				}
			}
			// The same standby still takes the next capture's attachment.
			attach, end2 := context.WithTimeout(ctx, 500*time.Millisecond)
			defer end2()
			a, err := router.Attach(attach, cluster, "77777777-7777-4777-8777-777777777777")
			if err != nil {
				t.Fatal("source delivery consumed the standby", err)
			}
			a.Close()
		})
	}
}
