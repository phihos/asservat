package targets

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
)

func TestRecorderSourceRetainsTargetPinAndOriginalInterval(t *testing.T) {
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	for _, mode := range []string{"exact", "legacy", "foreign-target", "extended-cutoff", "earlier-start", "expired", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			request := Request{ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: configuration.NamespaceRef{Name: "app", UID: "namespace"}, Workload: configuration.WorkloadRef{Kind: "Pod", Name: "app", UID: "pod"}, PodName: "app", PodUID: "pod"}
			target := PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: "namespace", Name: "app", UID: "pod"}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
			source := PacketSourceObservation{PodUID: "pod", NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: now, FreshUntil: target.FreshUntil}
			resolution := RecorderResolution{Target: target, Recorder: RecorderAnswer{Outcome: RecorderAvailable, Source: &source}}
			switch mode {
			case "legacy":
				resolution.Recorder.Source = nil
			case "foreign-target":
				source.PodUID = "other"
			case "extended-cutoff":
				source.FreshUntil = source.FreshUntil.Add(time.Nanosecond)
			case "earlier-start":
				source.ObservedAt = source.ObservedAt.Add(-time.Nanosecond)
			case "expired":
				source.FreshUntil = now
			case "unavailable":
				resolution.Recorder.Outcome = RecorderUnavailable
			}
			if !resolution.Valid(now) {
				t.Fatal("optional source facts changed metadata validity", mode)
			}
			if got, want := resolution.ValidSource(now), mode == "exact"; got != want {
				t.Fatal(mode, got, want)
			}
		})
	}
}
