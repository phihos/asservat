package bootstrap

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/collector"
)

type liveRuntimeNodes struct {
	recordingNodes
	snapshot collector.LiveRuntimeSnapshot
}

func (n liveRuntimeNodes) LiveRuntime(string) collector.LiveRuntimeSnapshot { return n.snapshot }

func TestResolveLiveRuntimeUsesOnlyCurrentAggregate(t *testing.T) {
	now := time.Now().UTC()
	request := collector.LiveRuntimeRequest{ClusterID: "00000000-0000-4000-8000-000000000001"}
	valid := collector.LiveRuntimeSnapshot{ClusterID: request.ClusterID, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Nodes: 1, RatesComplete: true, Live: &collector.LiveActivity{Cohorts: 1, ScanEvents: 2}}
	resolver := reportedTargets{recordings: &ConnectorRecordings{nodes: liveRuntimeNodes{snapshot: valid}, now: func() time.Time { return now }}}
	got, err := resolver.ResolveLiveRuntime(context.Background(), request)
	if err != nil || got.ClusterID != request.ClusterID || got.Live.ScanEvents != 2 {
		t.Fatal(got, err)
	}
	for name, mutate := range map[string]func(*collector.LiveRuntimeSnapshot){
		"wrong cluster": func(s *collector.LiveRuntimeSnapshot) { s.ClusterID = "00000000-0000-4000-8000-000000000002" },
		"stale":         func(s *collector.LiveRuntimeSnapshot) { s.FreshUntil = now },
		"bad rates":     func(s *collector.LiveRuntimeSnapshot) { s.RatesUnavailable = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			resolver.recordings.nodes = liveRuntimeNodes{snapshot: changed}
			if _, err := resolver.ResolveLiveRuntime(context.Background(), request); err == nil {
				t.Fatal("invalid aggregate accepted")
			}
		})
	}
}
