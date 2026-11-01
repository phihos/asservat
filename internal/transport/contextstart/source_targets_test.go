package contextstart

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

func maximumOngoingBatch(count int) ([]targets.OngoingRecorderRequest, []targets.OngoingRecorderResolution) {
	w, _ := sourceStreamWorkFixture()
	now := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	if now.After(time.Now()) {
		now = now.Add(-time.Second)
	}
	requests := make([]targets.OngoingRecorderRequest, count)
	values := make([]targets.OngoingRecorderResolution, count)
	for i := range requests {
		id := fmt.Sprintf("11111111-1111-4111-8111-%012x", i)
		r := w.Target.Request
		r.Namespace.Name = strings.Repeat("n", 63)
		r.Workload.Name = strings.Repeat("w", 253)
		r.PodName = strings.Repeat("p", 240) + fmt.Sprintf("%013d", i)
		r.PodUID = id
		requests[i] = targets.OngoingRecorderRequest{Target: r, SourceID: id, Fence: id}
		p := w.Target
		p.ObservedAt = now
		p.FreshUntil = now.Add(5 * time.Second)
		p.Request = r
		p.Pin = artifact.PinnedPod{Namespace: r.Namespace.Name, NamespaceUID: r.Namespace.UID, Name: r.PodName, UID: id, ControllerUID: id}
		p.PodResourceVersion = strings.Repeat("9", 128)
		p.WorkloadResourceVersion = strings.Repeat("9", 128)
		node := w.Node
		node.ObservedAt = now
		node.FreshUntil = now.Add(5 * time.Second)
		node.PodUID = id
		values[i] = targets.OngoingRecorderResolution{Recorder: targets.RecorderResolution{Target: p, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &node}}, Ceilings: targets.RecorderSourceCeilings{MaxActiveSources: collector.MaxActiveSources, InputBytesPerSecond: collector.MaxInputRate, InputBurstBytes: collector.MaxInputBurst, RingBytes: collector.MaxNodeRingBytes, FrozenBytes: collector.MaxNodeFrozenBytes}, ReportedAt: now, ReportFreshUntil: now.Add(collector.StatusStaleAfter), State: &targets.RecorderSourceState{SourceID: id, Fence: id, IssuedAt: now, LeafUntil: now.Add(30 * time.Second), ObservedAt: now, FreshUntil: now.Add(collector.StatusStaleAfter), Credit: 1<<63 - 1, ObservedBytes: 1<<63 - 2}}
	}
	return requests, values
}

func TestSourceBatchOneRouterQueryPreservesOrderPartialRefusalAndOriginalAsOf(t *testing.T) {
	requests, values := maximumOngoingBatch(3)
	now := values[0].Recorder.Target.ObservedAt
	work := workFixture()
	cluster := requests[0].Target.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	hub := Targets{Router: router, Now: func() time.Time { return now }}
	type result struct {
		values []targets.OngoingRecorderResolution
		err    error
	}
	done := make(chan result, 1)
	go func() { got, err := hub.ResolveOngoingRecorders(ctx, requests); done <- result{got, err} }()
	var job *queryJob
	select {
	case job = <-standby.query:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if job.method != queryResolveOngoingRecorders {
		t.Fatal("did not use one batch query", job.method)
	}
	in := job.in.([]targets.OngoingRecorderRequest)
	if len(in) != 3 || in[0] != requests[0] || in[2] != requests[2] {
		t.Fatal("input order changed")
	}
	values[1] = targets.OngoingRecorderResolution{} // one deleted/unavailable Pod
	*job.out.(*[]targets.OngoingRecorderResolution) = values
	end := now.Add(2 * time.Second)
	job.result <- queryResult{until: end}
	got := <-done
	if got.err != nil || len(got.values) != 3 {
		t.Fatal("one unavailable target denied completed other items", got.err)
	}
	if got.values[1].Recorder.Recorder.Outcome != targets.RecorderUnavailable || got.values[1].State != nil {
		t.Fatal("unavailable row fabricated state")
	}
	for _, i := range []int{0, 2} {
		if !got.values[i].Recorder.ValidSource(now) || got.values[i].Recorder.Target.Request != requests[i].Target || !got.values[i].Recorder.Recorder.Source.FreshUntil.Equal(end) || !got.values[i].ReportedAt.Equal(values[i].ReportedAt) {
			t.Fatal("batch changed identity/originalcutoff/asof", i)
		}
	}
}

func TestSourceBatchMaximumNamesFitExistingQueryFrame(t *testing.T) {
	requests, values := maximumOngoingBatch(targets.OngoingRecorderBatchLimit)
	if !targets.ValidOngoingRecorderBatch(requests) {
		t.Fatal("maximum workload batch invalid")
	}
	for name, value := range map[string]any{"request": requests, "reply": values} {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%d maximum-name %s rows: %d bytes", len(requests), name, len(body))
		if len(body) > contracts.APIContextOperationBytes-1024 {
			t.Fatal("batch cannot fit existing frame with reserved envelope", name, len(body))
		}
	}
}
