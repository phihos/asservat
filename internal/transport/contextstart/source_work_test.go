package contextstart

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"context"
	"errors"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
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

// Synthetic admitted authority/queue, actual source framing and original
// peer leases. Real signature purpose/key checks have their separate JOSE test.
func TestSourceWorkUsesBoundedRegionalConversationWithoutCapture(t *testing.T) {
	for _, mode := range []string{"arm", "stop", "queue-refusal"} {
		t.Run(mode, func(t *testing.T) {
			w, r := sourceStreamWorkFixture()
			if mode == "stop" {
				w = app.SourceWork{Channel: w.Channel, Source: collector.PacketSource{Permit: collector.SourcePermit{Binding: w.Source.Permit.Binding}}, Stop: true, StopIssuedAt: w.Source.Permit.IssuedAt, NotAfter: w.NotAfter}
			}
			if !w.Valid(time.Now()) {
				t.Fatal("invalid synthetic source work")
			}
			ctx, cancel := context.WithDeadline(t.Context(), w.NotAfter)
			defer cancel()
			hub, region := historyStreamPair(t, ctx, r)
			queue := &sourceQueue{fail: mode == "queue-refusal"}
			local := &SourceLocal{Queue: queue, Verifier: sourceWorkVerifierFunc(func(ctx context.Context, b []byte, current fleet.APIContextReceiver) (app.AuthenticatedSourceWork, error) {
				if current.Channel != w.Channel || string(b) != "synthetic-source-signature" {
					return app.AuthenticatedSourceWork{}, fleet.ErrDenied
				}
				return app.AuthenticatedSourceWork{Work: w, KeyID: "synthetic", TrustRevision: workFixture().TrustRevision, VerifiedAt: w.IssuedAt(), ValidUntil: w.NotAfter}, nil
			})}
			done := make(chan error, 1)
			go func() {
				f, current, err := region.AwaitWork(ctx)
				if err == nil && f.Kind == contracts.SourceWorkFrame {
					err = serveRegionalSource(ctx, region, current, f.Payload, local, time.Now)
				}
				clear(f.Payload)
				done <- err
			}()
			err := serveHubSource(ctx, hub, w, []byte("synthetic-source-signature"), time.Now)
			if mode == "queue-refusal" {
				if !errors.Is(err, fleet.ErrUnavailable) {
					t.Fatal("queue refusal lost", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal("regional protocol", err)
			}
			if queue.calls != 1 {
				t.Fatal("uncertain enqueue replayed", queue.calls)
			}
			if mode == "arm" && queue.last != w.Source.Permit {
				t.Fatal("original source grant changed")
			}
		})
	}
}
